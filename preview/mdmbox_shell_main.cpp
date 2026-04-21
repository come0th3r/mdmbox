#include "mdmbox_shell_window.h"

#include <QApplication>

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    MdmBoxShellWindow window;
    window.show();
    return app.exec();
}
