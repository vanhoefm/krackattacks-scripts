TEMPLATE	= app
LANGUAGE	= C++

CONFIG	+= qt warn_on release

DEFINES += CONFIG_CTRL_IFACE

win32 {
  LIBS += -lws2_32 -static
  DEFINES += CONFIG_NATIVE_WINDOWS CONFIG_CTRL_IFACE_NAMED_PIPE
  SOURCES += ../../src/utils/os_win32.c
} else:win32-g++ {
  # cross compilation to win32
  LIBS += -lws2_32 -static
  DEFINES += CONFIG_NATIVE_WINDOWS CONFIG_CTRL_IFACE_NAMED_PIPE
  SOURCES += ../../src/utils/os_win32.c
} else {
  DEFINES += CONFIG_CTRL_IFACE_UNIX
  SOURCES += ../../src/utils/os_unix.c
}

INCLUDEPATH	+= . .. ../../src/utils ../../src/common

HEADERS	+= wpamsg.h \
	wpagui.h \
	eventhistory.h \
	scanresults.h \
	userdatarequest.h \
	networkconfig.h

SOURCES	+= main.cpp \
	wpagui.cpp \
	eventhistory.cpp \
	scanresults.cpp \
	userdatarequest.cpp \
	networkconfig.cpp \
	../../src/common/wpa_ctrl.c

FORMS	= wpagui.ui \
	eventhistory.ui \
	scanresults.ui \
	userdatarequest.ui \
	networkconfig.ui


unix {
  UI_DIR = .ui
  MOC_DIR = .moc
  OBJECTS_DIR = .obj
}
