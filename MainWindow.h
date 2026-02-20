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

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);

private slots:
    void onLoginClicked();
    void onLogoutClicked();
    void onLoginFinished();
    void onUsersFinished();
    void onSslErrors(QNetworkReply *reply, const QList<QSslError> &errors);

private:
    void buildUi();
    void showLogin();
    void showUsers();
    void loadUsers();
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

    // Users UI
    QWidget *_usersPage = nullptr;
    QLabel *_loginInfo = nullptr;
    QPushButton *_logoutButton = nullptr;
    QTableWidget *_usersTable = nullptr;
    QLabel *_usersError = nullptr;

    QNetworkReply *_loginReply = nullptr;
    QNetworkReply *_usersReply = nullptr;
};
