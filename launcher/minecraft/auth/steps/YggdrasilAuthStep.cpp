#include "YggdrasilAuthStep.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkRequest>
#include <QUrl>
#include <QUuid>

#include "Application.h"
#include "Logging.h"
#include "net/NetUtils.h"
#include "net/RawHeaderProxy.h"
#include "net/Request.h"

YggdrasilAuthStep::YggdrasilAuthStep(AccountData* data, bool refresh) : AuthStep(data), m_refresh(refresh) {}

QString YggdrasilAuthStep::describe()
{
    return m_refresh ? tr("Refreshing Yggdrasil session") : tr("Logging in to Yggdrasil server");
}

static QString normalizeServer(const QString& server)
{
    QString s = server.trimmed();
    while (s.endsWith('/')) {
        s.chop(1);
    }
    return s;
}

void YggdrasilAuthStep::perform()
{
    QString server = normalizeServer(m_data->yggdrasilServer);
    if (server.isEmpty()) {
        emit finished(AccountTaskState::STATE_FAILED_SOFT, tr("Yggdrasil server URL is empty."));
        return;
    }

    QString clientToken = m_data->yggdrasilToken.extra.value("clientToken").toString();
    if (clientToken.isEmpty()) {
        clientToken = QUuid::createUuid().toString(QUuid::Id128);
        m_data->yggdrasilToken.extra["clientToken"] = clientToken;
    }

    QUrl url;
    QByteArray body;
    if (m_refresh && !m_data->yggdrasilToken.token.isEmpty()) {
        url = QUrl(server + "/authserver/refresh");
        QJsonObject obj;
        obj["accessToken"] = m_data->yggdrasilToken.token;
        obj["clientToken"] = clientToken;
        if (!m_data->minecraftProfile.id.isEmpty()) {
            QJsonObject profile;
            profile["id"] = m_data->minecraftProfile.id;
            profile["name"] = m_data->minecraftProfile.name;
            obj["selectedProfile"] = profile;
        }
        body = QJsonDocument(obj).toJson(QJsonDocument::Compact);
    } else {
        url = QUrl(server + "/authserver/authenticate");
        QString username = m_data->yggdrasilToken.extra.value("username").toString();
        QString password = m_data->yggdrasilToken.extra.value("password").toString();
        if (username.isEmpty()) {
            username = m_data->yggdrasilToken.extra.value("userName").toString();
        }
        QJsonObject obj;
        obj["username"] = username;
        obj["password"] = password;
        obj["clientToken"] = clientToken;
        obj["requestUser"] = true;
        body = QJsonDocument(obj).toJson(QJsonDocument::Compact);
    }

    auto headers = QList<Net::HeaderPair>{
        { "Content-Type", "application/json" },
        { "Accept", "application/json" },
    };

    auto [request, response] = Net::Request::makeByteArray(url, body);
    m_request = request;
    m_request->addHeaderProxy(std::make_unique<Net::RawHeaderProxy>(headers));
    m_request->enableAutoRetry(true);

    m_task.reset(new NetJob("YggdrasilAuthStep", APPLICATION->network()));
    m_task->setAskRetry(false);
    m_task->addNetAction(m_request);

    connect(m_task.get(), &Task::finished, this, [this, response] { onRequestDone(response); });

    m_task->start();
    qDebug() << "Yggdrasil auth request to" << url;
}

void YggdrasilAuthStep::onRequestDone(QByteArray* response)
{
    if (m_request->error() != QNetworkReply::NoError) {
        qWarning() << "Reply error:" << m_request->error();
        if (Net::isApplicationError(m_request->error()) && !Net::isServerError(m_request->error())) {
            emit finished(AccountTaskState::STATE_FAILED_SOFT,
                          tr("Failed to authenticate with Yggdrasil server: %1").arg(m_request->errorString()));
        } else {
            m_data->networkError = m_request->error();
            emit finished(AccountTaskState::STATE_OFFLINE, tr("Failed to authenticate with Yggdrasil server: %1").arg(m_request->errorString()));
        }
        return;
    }

    QJsonDocument doc = QJsonDocument::fromJson(*response);
    if (!doc.isObject()) {
        emit finished(AccountTaskState::STATE_FAILED_SOFT, tr("Invalid response from Yggdrasil server."));
        return;
    }
    QJsonObject obj = doc.object();

    if (obj.contains("error")) {
        QString err = obj.value("errorMessage").toString();
        if (err.isEmpty()) {
            err = obj.value("error").toString();
        }
        emit finished(AccountTaskState::STATE_FAILED_SOFT, tr("Yggdrasil error: %1").arg(err));
        return;
    }

    QString accessToken = obj.value("accessToken").toString();
    QString clientToken = obj.value("clientToken").toString();
    if (clientToken.isEmpty()) {
        clientToken = m_data->yggdrasilToken.extra.value("clientToken").toString();
    }

    QJsonObject selectedProfile = obj.value("selectedProfile").toObject();
    if (selectedProfile.isEmpty()) {
        QJsonArray available = obj.value("availableProfiles").toArray();
        if (!available.isEmpty() && available.first().isObject()) {
            selectedProfile = available.first().toObject();
        }
    }

    if (accessToken.isEmpty() || selectedProfile.isEmpty()) {
        emit finished(AccountTaskState::STATE_FAILED_SOFT, tr("Yggdrasil response missing access token or profile."));
        return;
    }

    m_data->yggdrasilToken.token = accessToken;
    m_data->yggdrasilToken.refresh_token.clear();
    m_data->yggdrasilToken.extra["clientToken"] = clientToken;
    m_data->yggdrasilToken.extra.remove("password");
    m_data->yggdrasilToken.issueInstant = QDateTime::currentDateTimeUtc();
    m_data->yggdrasilToken.notAfter = QDateTime::currentDateTimeUtc().addSecs(24 * 3600);
    m_data->yggdrasilToken.validity = Validity::Certain;

    m_data->minecraftProfile.id = selectedProfile.value("id").toString();
    m_data->minecraftProfile.name = selectedProfile.value("name").toString();
    m_data->minecraftProfile.validity = Validity::Certain;

    m_data->minecraftEntitlement.ownsMinecraft = true;
    m_data->minecraftEntitlement.canPlayMinecraft = true;
    m_data->minecraftEntitlement.validity = Validity::Certain;

    m_data->validity_ = Validity::Certain;

    emit finished(AccountTaskState::STATE_WORKING, tr("Authenticated with Yggdrasil server"));
}