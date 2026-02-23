#pragma once

#include <QMainWindow>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QStackedWidget>
#include <QLineEdit>
#include <QCheckBox>
#include <QPushButton>
#include <QLabel>
#include <QTableWidget>
#include <QSettings>
#include <QComboBox>

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);

private slots:
    void onLoginClicked();
    void onLogoutClicked();
    void onLoginFinished();
    void onProductsFinished();
    void onSslErrors(QNetworkReply *reply, const QList<QSslError> &errors);

private:
    void buildUi();
    void showLogin();
    void showInventory();
    void loadProducts();
    QUrl makeApiUrl(const QString &path) const;
    void setError(const QString &message);

    QNetworkAccessManager _network;
    QString _accessToken;

    QStackedWidget *_stack = nullptr;

    // Login UI
    QWidget *_loginPage = nullptr;
    QLineEdit *_apiUrlInput = nullptr;
    QCheckBox *_rememberUrl = nullptr;
    QLineEdit *_usernameInput = nullptr;
    QLineEdit *_passwordInput = nullptr;
    QLabel *_loginError = nullptr;
    QPushButton *_loginButton = nullptr;

    // Inventory UI
    QWidget *_inventoryPage = nullptr;
    QLabel *_loginInfo = nullptr;
    QPushButton *_logoutButton = nullptr;
    QPushButton *_refreshButton = nullptr;
    QLineEdit *_searchInput = nullptr;
    QComboBox *_conditionFilter = nullptr;
    QTableWidget *_productsTable = nullptr;
    QLabel *_inventoryError = nullptr;
    QLabel *_inventoryStatus = nullptr;

    QNetworkReply *_loginReply = nullptr;
    QNetworkReply *_productsReply = nullptr;
};
