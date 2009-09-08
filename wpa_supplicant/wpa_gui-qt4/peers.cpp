/*
 * wpa_gui - Peers class
 * Copyright (c) 2009, Atheros Communications
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#include <QImageReader>

#include "wpagui.h"
#include "peers.h"

/*
 * TODO:
 * - add pending WPS queries (from M1/PIN, PBC?)
 * - add current AP info (e.g., from WPS) in station mode
 * - different icons to indicate peer type
 */

Peers::Peers(QWidget *parent, const char *, bool, Qt::WFlags)
	: QDialog(parent)
{
	setupUi(this);

	connect(peers, SIGNAL(clicked(QModelIndex)), this,
		SLOT(clicked(QModelIndex)));

	if (QImageReader::supportedImageFormats().contains(QByteArray("svg")))
		default_icon = new QIcon(":/icons/wpa_gui.svg");
	else
		default_icon = new QIcon(":/icons/wpa_gui.png");

	peers->setModel(&model);
	peers->setResizeMode(QListView::Adjust);

	wpagui = NULL;
}


void Peers::setWpaGui(WpaGui *_wpagui)
{
	wpagui = _wpagui;
	update_peers();
}


Peers::~Peers()
{
	delete default_icon;
}


void Peers::languageChange()
{
	retranslateUi(this);
}


void Peers::clicked(const QModelIndex & /*index*/)
{
	/* QStandardItem *item = model.itemFromIndex(index); */
	/* TODO: give an option to provide PIN for WPS, etc. */
	/* printf("Clicked: %s\n", item->text().toAscii().constData()); */
}


void Peers::update_peers()
{
	char reply[2048];
	size_t reply_len;
	char cmd[20];
	int res;

	model.clear();
	if (wpagui == NULL)
		return;

	reply_len = sizeof(reply) - 1;
	if (wpagui->ctrlRequest("STA-FIRST", reply, &reply_len) < 0)
		return;

	do {
		reply[reply_len] = '\0';
		QString info(reply);
		char *txt = reply;
		while (*txt != '\0' && *txt != '\n')
			txt++;
		*txt++ = '\0';
		if (strncmp(reply, "FAIL", 4) == 0)
			break;

		QStringList lines = info.split(QRegExp("\\n"));
		QString name;

		for (QStringList::Iterator it = lines.begin();
		     it != lines.end(); it++) {
			int pos = (*it).indexOf('=') + 1;
			if (pos < 1)
				continue;

			if ((*it).startsWith("wpsDeviceName="))
				name = (*it).mid(pos);
		}

		if (name.isEmpty())
			name = reply;

		QStandardItem *item = new QStandardItem(*default_icon, name);
		if (item) {
			item->setToolTip(info);
			model.appendRow(item);
		}

		reply_len = sizeof(reply) - 1;
		snprintf(cmd, sizeof(cmd), "STA-NEXT %s", reply);
		res = wpagui->ctrlRequest(cmd, reply, &reply_len);
	} while (res >= 0);
}
