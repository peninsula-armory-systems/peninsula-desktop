#include "MainWindow.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QHeaderView>
#include <QSslConfiguration>
#include <QSslSocket>

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
    buildUi();

    connect(_loginButton, &QPushButton::clicked, this, &MainWindow::onLoginClicked);
    connect(_logoutButton, &QPushButton::clicked, this, &MainWindow::onLogoutClicked);
    connect(&_network, &QNetworkAccessManager::sslErrors, this, &MainWindow::onSslErrors);

    showLogin();
}

void MainWindow::buildUi() {
    setWindowTitle("Peninsula Client");
    resize(900, 600);

    setStyleSheet(
        "QMainWindow { background: #121212; }"
        "QLabel { color: #e0e0e0; }"
        "QLineEdit { background: #1e1e1e; color: #e0e0e0; border: 1px solid #2a2a2a; padding: 6px; }"
        "QCheckBox { color: #e0e0e0; }"
        "QPushButton { background: #1e1e1e; color: #e0e0e0; border: 1px solid #2a2a2a; padding: 6px 10px; }"
        "QPushButton:pressed { background: #2a2a2a; }"
        "QTableWidget { background: #1a1a1a; color: #e0e0e0; gridline-color: #2a2a2a; }"
        "QHeaderView::section { background: #1e1e1e; color: #e0e0e0; border: 1px solid #2a2a2a; padding: 6px; }"
    );

    _stack = new QStackedWidget(this);
    setCentralWidget(_stack);

    // Login Page
    _loginPage = new QWidget(this);
    auto *loginLayout = new QVBoxLayout(_loginPage);
    loginLayout->setSpacing(12);
    loginLayout->setContentsMargins(40, 40, 40, 40);

    auto *title = new QLabel("Peninsula Client", _loginPage);
    title->setStyleSheet("font-size: 20px; font-weight: 600;");
    loginLayout->addWidget(title, 0, Qt::AlignHCenter);

    auto *apiLabel = new QLabel("API URL", _loginPage);
    _apiUrlInput = new QLineEdit("http://localhost:4875", _loginPage);
    _rememberUrl = new QCheckBox("Remember URL", _loginPage);

    QSettings settings("peninsula", "client");
    const auto savedUrl = settings.value("api_url").toString();
    if (!savedUrl.isEmpty()) {
        _apiUrlInput->setText(savedUrl);
        _rememberUrl->setChecked(true);
    }
    loginLayout->addWidget(apiLabel);
    loginLayout->addWidget(_apiUrlInput);
    loginLayout->addWidget(_rememberUrl);

    auto *userLabel = new QLabel("Username", _loginPage);
    _usernameInput = new QLineEdit(_loginPage);
    auto *passLabel = new QLabel("Password", _loginPage);
    _passwordInput = new QLineEdit(_loginPage);
    _passwordInput->setEchoMode(QLineEdit::Password);

    loginLayout->addWidget(userLabel);
    loginLayout->addWidget(_usernameInput);
    loginLayout->addWidget(passLabel);
    loginLayout->addWidget(_passwordInput);

    _loginError = new QLabel(_loginPage);
    _loginError->setStyleSheet("color: #ff6b6b;");
    _loginError->setWordWrap(true);
    loginLayout->addWidget(_loginError);

    _loginButton = new QPushButton("Login", _loginPage);
    _loginButton->setMinimumHeight(36);
    loginLayout->addWidget(_loginButton);

    loginLayout->addStretch();

    // Users Page
    _usersPage = new QWidget(this);
    auto *usersLayout = new QVBoxLayout(_usersPage);
    usersLayout->setSpacing(10);
    usersLayout->setContentsMargins(20, 20, 20, 20);

    auto *headerLayout = new QHBoxLayout();
    _loginInfo = new QLabel(_usersPage);
    _logoutButton = new QPushButton("Logout", _usersPage);
    _logoutButton->setFixedWidth(90);
    headerLayout->addWidget(_loginInfo);
    headerLayout->addStretch();
    headerLayout->addWidget(_logoutButton);
    usersLayout->addLayout(headerLayout);

    _usersTable = new QTableWidget(_usersPage);
    _usersTable->setColumnCount(4);
    _usersTable->setHorizontalHeaderLabels({"ID", "Username", "Role", "Created At"});
    _usersTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    _usersTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    _usersTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    _usersTable->setSelectionMode(QAbstractItemView::SingleSelection);
    usersLayout->addWidget(_usersTable);

    _usersError = new QLabel(_usersPage);
    _usersError->setStyleSheet("color: #ff6b6b;");
    _usersError->setWordWrap(true);
    usersLayout->addWidget(_usersError);

    _stack->addWidget(_loginPage);
    _stack->addWidget(_usersPage);
}

void MainWindow::showLogin() {
    _loginError->clear();
    _usersError->clear();
    _stack->setCurrentWidget(_loginPage);
}

void MainWindow::showUsers() {
    _usersError->clear();
    _stack->setCurrentWidget(_usersPage);
}

void MainWindow::setError(const QString &message) {
    _loginError->setText(message);
}

QUrl MainWindow::makeApiUrl(const QString &path) const {
    QString base = _apiUrlInput->text().trimmed();
    if (!base.endsWith('/')) {
        base.append('/');
    }
    return QUrl(base + path);
}

void MainWindow::onLoginClicked() {
    _loginError->clear();

    const auto apiUrl = _apiUrlInput->text().trimmed();
    const auto username = _usernameInput->text().trimmed();
    const auto password = _passwordInput->text();

    if (apiUrl.isEmpty() || username.isEmpty() || password.isEmpty()) {
        setError("API URL, username et password requis.");
        return;
    }

    if (_rememberUrl->isChecked()) {
        QSettings settings("peninsula", "client");
        settings.setValue("api_url", apiUrl);
    } else {
        QSettings settings("peninsula", "client");
        settings.remove("api_url");
    }

    QJsonObject payload;
    payload["username"] = username;
    payload["password"] = password;

    const auto url = makeApiUrl("v1/auth/login");
    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    if (_loginReply) {
        _loginReply->deleteLater();
    }

    _loginReply = _network.post(request, QJsonDocument(payload).toJson());
    connect(_loginReply, &QNetworkReply::finished, this, &MainWindow::onLoginFinished);
}

void MainWindow::onLoginFinished() {
    if (!_loginReply) return;

    const auto reply = _loginReply;
    _loginReply = nullptr;

    const auto status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    const auto body = reply->readAll();

    reply->deleteLater();

    if (status < 200 || status >= 300) {
        QJsonParseError error;
        auto doc = QJsonDocument::fromJson(body, &error);
        if (error.error == QJsonParseError::NoError && doc.isObject()) {
            const auto msg = doc.object().value("error").toString();
            setError(msg.isEmpty() ? "Login échoué" : msg);
        } else {
            setError("Login échoué");
        }
        return;
    }

    const auto doc = QJsonDocument::fromJson(body);
    if (!doc.isObject()) {
        setError("Réponse invalide.");
        return;
    }

    const auto token = doc.object().value("accessToken").toString();
    if (token.isEmpty()) {
        setError("Token manquant.");
        return;
    }

    _accessToken = token;
    _loginInfo->setText("Connecté");
    _passwordInput->clear();
    _usernameInput->clear();

    showUsers();
    loadUsers();
}

void MainWindow::onUsersFinished() {
    if (!_usersReply) return;

    const auto reply = _usersReply;
    _usersReply = nullptr;

    const auto status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    const auto body = reply->readAll();

    reply->deleteLater();

    if (status < 200 || status >= 300) {
        QJsonParseError error;
        auto doc = QJsonDocument::fromJson(body, &error);
        if (error.error == QJsonParseError::NoError && doc.isObject()) {
            const auto msg = doc.object().value("error").toString();
            _usersError->setText(msg.isEmpty() ? "Erreur API" : msg);
        } else {
            _usersError->setText("Erreur API");
        }
        return;
    }

    QJsonParseError error;
    auto doc = QJsonDocument::fromJson(body, &error);
    if (error.error != QJsonParseError::NoError || !doc.isObject()) {
        _usersError->setText("Réponse invalide");
        return;
    }

    const auto users = doc.object().value("users").toArray();
    _usersTable->setRowCount(users.size());

    for (int i = 0; i < users.size(); ++i) {
        const auto obj = users.at(i).toObject();
        _usersTable->setItem(i, 0, new QTableWidgetItem(QString::number(obj.value("id").toInt())));
        _usersTable->setItem(i, 1, new QTableWidgetItem(obj.value("username").toString()));
        _usersTable->setItem(i, 2, new QTableWidgetItem(obj.value("role").toString()));
        _usersTable->setItem(i, 3, new QTableWidgetItem(obj.value("created_at").toString()));
    }
}

void MainWindow::loadUsers() {
    if (_usersReply) {
        _usersReply->deleteLater();
    }

    const auto url = makeApiUrl("v1/admin/users/list");
    QNetworkRequest request(url);
    request.setRawHeader("Authorization", QString("Bearer %1").arg(_accessToken).toUtf8());

    _usersReply = _network.get(request);
    connect(_usersReply, &QNetworkReply::finished, this, &MainWindow::onUsersFinished);
}

void MainWindow::onLogoutClicked() {
    _accessToken.clear();
    showLogin();
}

void MainWindow::onSslErrors(QNetworkReply *reply, const QList<QSslError> &errors) {
    Q_UNUSED(errors);
    reply->ignoreSslErrors();
}
