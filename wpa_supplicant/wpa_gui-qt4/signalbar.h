/*
 * wpa_gui - SignalBar class
 * Copyright (c) 2011, Kel Modderman <kel@otaku42.de>
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

#ifndef SIGNALBAR_H
#define SIGNALBAR_H

#include <QObject>
#include <QStyledItemDelegate>

class SignalBar : public QStyledItemDelegate
{
	Q_OBJECT

public:
	SignalBar(QObject *parent = 0);
	~SignalBar();

	virtual void paint(QPainter *painter,
			   const QStyleOptionViewItem &option,
			   const QModelIndex &index) const ;
};

#endif /* SIGNALBAR_H */
