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
    connect(_refreshButton, &QPushButton::clicked, this, &MainWindow::loadProducts);
    connect(&_network, &QNetworkAccessManager::sslErrors, this, &MainWindow::onSslErrors);

    showLogin();
}

void MainWindow::buildUi() {
    setWindowTitle("Peninsula Client");
    resize(1100, 700);

    setStyleSheet(
        "QMainWindow { background: #121212; }"
        "QLabel { color: #e0e0e0; }"
        "QLineEdit { background: #1e1e1e; color: #e0e0e0; border: 1px solid #2a2a2a; padding: 6px; }"
        "QCheckBox { color: #e0e0e0; }"
        "QComboBox { background: #1e1e1e; color: #e0e0e0; border: 1px solid #2a2a2a; padding: 4px 8px; }"
        "QComboBox QAbstractItemView { background: #1e1e1e; color: #e0e0e0; selection-background-color: #2a2a2a; }"
        "QPushButton { background: #1e1e1e; color: #e0e0e0; border: 1px solid #2a2a2a; padding: 6px 10px; }"
        "QPushButton:pressed { background: #2a2a2a; }"
        "QPushButton:hover { border-color: #4a9eff; }"
        "QTableWidget { background: #1a1a1a; color: #e0e0e0; gridline-color: #2a2a2a; border: 1px solid #2a2a2a; }"
        "QHeaderView::section { background: #1e1e1e; color: #e0e0e0; border: 1px solid #2a2a2a; padding: 6px; font-weight: bold; }"
    );

    _stack = new QStackedWidget(this);
    setCentralWidget(_stack);

    // ── Login Page ──────────────────────────────────────
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

    // ── Inventory Page ──────────────────────────────────
    _inventoryPage = new QWidget(this);
    auto *invLayout = new QVBoxLayout(_inventoryPage);
    invLayout->setSpacing(10);
    invLayout->setContentsMargins(20, 20, 20, 20);

    // Header: info + logout
    auto *headerLayout = new QHBoxLayout();
    _loginInfo = new QLabel(_inventoryPage);
    _logoutButton = new QPushButton("Déconnexion", _inventoryPage);
    _logoutButton->setFixedWidth(110);
    headerLayout->addWidget(_loginInfo);
    headerLayout->addStretch();
    headerLayout->addWidget(_logoutButton);
    invLayout->addLayout(headerLayout);

    // Toolbar: search + filter + refresh
    auto *toolbarLayout = new QHBoxLayout();

    _searchInput = new QLineEdit(_inventoryPage);
    _searchInput->setPlaceholderText("Rechercher (nom, SKU, marque)...");
    _searchInput->setMinimumWidth(300);
    toolbarLayout->addWidget(_searchInput);

    _conditionFilter = new QComboBox(_inventoryPage);
    _conditionFilter->addItem("Tous", "");
    _conditionFilter->addItem("Neuf", "new");
    _conditionFilter->addItem("Occasion", "used");
    _conditionFilter->addItem("Reconditionné", "refurbished");
    _conditionFilter->setFixedWidth(140);
    toolbarLayout->addWidget(_conditionFilter);

    _refreshButton = new QPushButton("Actualiser", _inventoryPage);
    _refreshButton->setFixedWidth(100);
    toolbarLayout->addWidget(_refreshButton);

    invLayout->addLayout(toolbarLayout);

    // Connect search/filter to reload
    connect(_searchInput, &QLineEdit::returnPressed, this, &MainWindow::loadProducts);
    connect(_conditionFilter, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this]() {
        loadProducts();
    });

    // Products table
    _productsTable = new QTableWidget(_inventoryPage);
    _productsTable->setColumnCount(7);
    _productsTable->setHorizontalHeaderLabels({
        "SKU", "Nom", "Marque", "État", "Prix", "Stock", "Catégorie"
    });
    _productsTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    _productsTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    _productsTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    _productsTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    _productsTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    _productsTable->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
    _productsTable->horizontalHeader()->setSectionResizeMode(6, QHeaderView::ResizeToContents);
    _productsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    _productsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    _productsTable->setSelectionMode(QAbstractItemView::SingleSelection);
    _productsTable->setAlternatingRowColors(true);
    _productsTable->setStyleSheet(
        "QTableWidget { alternate-background-color: #1e1e1e; }"
    );
    invLayout->addWidget(_productsTable);

    // Status bar
    auto *bottomLayout = new QHBoxLayout();
    _inventoryError = new QLabel(_inventoryPage);
    _inventoryError->setStyleSheet("color: #ff6b6b;");
    _inventoryError->setWordWrap(true);
    _inventoryStatus = new QLabel(_inventoryPage);
    _inventoryStatus->setStyleSheet("color: #888;");
    bottomLayout->addWidget(_inventoryError);
    bottomLayout->addStretch();
    bottomLayout->addWidget(_inventoryStatus);
    invLayout->addLayout(bottomLayout);

    _stack->addWidget(_loginPage);
    _stack->addWidget(_inventoryPage);
}

void MainWindow::showLogin() {
    _loginError->clear();
    _inventoryError->clear();
    _stack->setCurrentWidget(_loginPage);
}

void MainWindow::showInventory() {
    _inventoryError->clear();
    _stack->setCurrentWidget(_inventoryPage);
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
        setError("API URL, username and password are required.");
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
    qDebug() << "Login URL:" << url.toString();
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

    const auto networkError = reply->error();
    const auto status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    const auto body = reply->readAll();

    reply->deleteLater();

    // Network-level error (connection refused, timeout, DNS failure...)
    if (networkError != QNetworkReply::NoError && status == 0) {
        setError("Connexion impossible : " + reply->errorString());
        return;
    }

    if (status < 200 || status >= 300) {
        QJsonParseError error;
        auto doc = QJsonDocument::fromJson(body, &error);
        if (error.error == QJsonParseError::NoError && doc.isObject()) {
            const auto msg = doc.object().value("error").toString();
            setError(msg.isEmpty() ? "Login failed" : msg);
        } else {
            setError("Login failed");
        }
        return;
    }

    const auto doc = QJsonDocument::fromJson(body);
    if (!doc.isObject()) {
        setError("Invalid response.");
        return;
    }

    const auto token = doc.object().value("accessToken").toString();
    if (token.isEmpty()) {
        setError("Missing token.");
        return;
    }

    _accessToken = token;
    _loginInfo->setText("Connecté");
    _passwordInput->clear();
    _usernameInput->clear();

    showInventory();
    loadProducts();
}

void MainWindow::loadProducts() {
    if (_productsReply) {
        _productsReply->deleteLater();
    }

    _inventoryError->clear();
    _inventoryStatus->setText("Chargement...");

    // Build query string
    QString queryStr = "v1/products?limit=200";

    const auto search = _searchInput->text().trimmed();
    if (!search.isEmpty()) {
        queryStr += "&search=" + QUrl::toPercentEncoding(search);
    }

    const auto condition = _conditionFilter->currentData().toString();
    if (!condition.isEmpty()) {
        queryStr += "&condition=" + condition;
    }

    const auto url = makeApiUrl(queryStr);
    QNetworkRequest request(url);
    request.setRawHeader("Authorization", QString("Bearer %1").arg(_accessToken).toUtf8());

    _productsReply = _network.get(request);
    connect(_productsReply, &QNetworkReply::finished, this, &MainWindow::onProductsFinished);
}

void MainWindow::onProductsFinished() {
    if (!_productsReply) return;

    const auto reply = _productsReply;
    _productsReply = nullptr;

    const auto status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    const auto body = reply->readAll();

    reply->deleteLater();

    if (status < 200 || status >= 300) {
        QJsonParseError error;
        auto doc = QJsonDocument::fromJson(body, &error);
        if (error.error == QJsonParseError::NoError && doc.isObject()) {
            const auto msg = doc.object().value("error").toString();
            _inventoryError->setText(msg.isEmpty() ? "Erreur API" : msg);
        } else {
            _inventoryError->setText("Erreur API (HTTP " + QString::number(status) + ")");
        }
        _inventoryStatus->clear();
        return;
    }

    QJsonParseError error;
    auto doc = QJsonDocument::fromJson(body, &error);
    if (error.error != QJsonParseError::NoError || !doc.isObject()) {
        _inventoryError->setText("Réponse invalide");
        _inventoryStatus->clear();
        return;
    }

    const auto root = doc.object();
    const auto products = root.value("products").toArray();
    const auto total = root.value("total").toInt(products.size());

    _productsTable->setRowCount(products.size());

    for (int i = 0; i < products.size(); ++i) {
        const auto obj = products.at(i).toObject();

        const auto sku = obj.value("sku").toString();
        const auto name = obj.value("name").toString();
        const auto brand = obj.value("brand").toString();
        const auto condition = obj.value("condition").toString();
        // price peut être string ou number selon l'API
        const auto priceVal = obj.value("price");
        const auto price = priceVal.isString() ? priceVal.toString() : QString::number(priceVal.toDouble(), 'f', 2);

        // total_stock peut être string ou int (PostgreSQL SUM → bigint → string)
        const auto stockVal = obj.value("total_stock");
        const int stockTotal = stockVal.isString() ? stockVal.toString().toInt() : stockVal.toInt(0);
        const auto categoryName = obj.value("category_name").toString("-");

        // Condition display
        QString conditionDisplay = condition;
        if (condition == "new") conditionDisplay = "Neuf";
        else if (condition == "used") conditionDisplay = "Occasion";
        else if (condition == "refurbished") conditionDisplay = "Reconditionné";

        _productsTable->setItem(i, 0, new QTableWidgetItem(sku));
        _productsTable->setItem(i, 1, new QTableWidgetItem(name));
        _productsTable->setItem(i, 2, new QTableWidgetItem(brand));
        _productsTable->setItem(i, 3, new QTableWidgetItem(conditionDisplay));

        auto *priceItem = new QTableWidgetItem(price + " €");
        priceItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        _productsTable->setItem(i, 4, priceItem);

        auto *stockItem = new QTableWidgetItem(QString::number(stockTotal));
        stockItem->setTextAlignment(Qt::AlignCenter);
        if (stockTotal <= 0) {
            stockItem->setForeground(QColor("#ff6b6b"));
        } else if (stockTotal <= 2) {
            stockItem->setForeground(QColor("#ffa726"));
        }
        _productsTable->setItem(i, 5, stockItem);

        _productsTable->setItem(i, 6, new QTableWidgetItem(categoryName));
    }

    _inventoryStatus->setText(QString::number(products.size()) + " / " + QString::number(total) + " produits");
}

void MainWindow::onLogoutClicked() {
    _accessToken.clear();
    _productsTable->setRowCount(0);
    _inventoryStatus->clear();
    showLogin();
}

void MainWindow::onSslErrors(QNetworkReply *reply, const QList<QSslError> &errors) {
    Q_UNUSED(errors);
    reply->ignoreSslErrors();
}
