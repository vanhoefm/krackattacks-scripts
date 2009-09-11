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

#include <cstdio>
#include <QImageReader>
#include <QMessageBox>

#include "wpagui.h"
#include "stringquery.h"
#include "peers.h"


static const int peer_role_address = Qt::UserRole + 1;

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

	if (QImageReader::supportedImageFormats().contains(QByteArray("svg")))
		default_icon = new QIcon(":/icons/wpa_gui.svg");
	else
		default_icon = new QIcon(":/icons/wpa_gui.png");

	peers->setModel(&model);
	peers->setResizeMode(QListView::Adjust);

	peers->setContextMenuPolicy(Qt::CustomContextMenu);
	connect(peers, SIGNAL(customContextMenuRequested(const QPoint &)),
		this, SLOT(context_menu(const QPoint &)));

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


void Peers::context_menu(const QPoint &pos)
{
	QMenu *menu = new QMenu;
	if (menu == NULL)
		return;

	QModelIndex idx = peers->indexAt(pos);
	if (idx.isValid()) {
		ctx_item = model.itemFromIndex(idx);
		/* TODO: only for peers that are requesting WPS PIN method */
		menu->addAction(QString("Enter WPS PIN"), this,
				SLOT(enter_pin()));
	} else {
		ctx_item = NULL;
		menu->addAction(QString("Refresh"), this, SLOT(ctx_refresh()));
	}

	menu->exec(peers->mapToGlobal(pos));
}


void Peers::enter_pin()
{
	if (ctx_item == NULL)
		return;
	QString addr = ctx_item->data(peer_role_address).toString();
	StringQuery input(tr("PIN:"));
	input.setWindowTitle(tr("PIN for ") + ctx_item->text());
	if (input.exec() != QDialog::Accepted)
		return;

	char cmd[100];
	char reply[100];
	size_t reply_len;
	snprintf(cmd, sizeof(cmd), "WPS_PIN %s %s",
		 addr.toAscii().constData(),
		 input.get_string().toAscii().constData());
	reply_len = sizeof(reply) - 1;
	if (wpagui->ctrlRequest(cmd, reply, &reply_len) < 0) {
		QMessageBox msg;
		msg.setIcon(QMessageBox::Warning);
		msg.setText("Failed to set the WPS PIN.");
		msg.exec();
	}
}


void Peers::ctx_refresh()
{
	update_peers();
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
		if (strncmp(reply, "FAIL", 4) == 0 ||
		    strncmp(reply, "UNKNOWN", 7) == 0)
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
			item->setData(QString(reply), peer_role_address);
			item->setToolTip(info);
			model.appendRow(item);
		}

		reply_len = sizeof(reply) - 1;
		snprintf(cmd, sizeof(cmd), "STA-NEXT %s", reply);
		res = wpagui->ctrlRequest(cmd, reply, &reply_len);
	} while (res >= 0);
}
