/*
 * wpadebug - wpa_supplicant and Wi-Fi debugging app for Android
 * Copyright (c) 2013, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

package w1.fi.wpadebug;

import android.app.Activity;
import android.os.Bundle;
import android.os.Parcelable;
import android.view.MenuItem;
import android.content.Intent;
import android.widget.TextView;
import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.NfcAdapter;

public class WpaNfcActivity extends Activity
{
    private static final String TAG = "wpadebug";

    String byteArrayHex(byte[] a) {
	StringBuilder sb = new StringBuilder();
	for (byte b: a)
	    sb.append(String.format("%02x", b));
	return sb.toString();
    }

    @Override
    public void onCreate(Bundle savedInstanceState)
    {
	Log.d(TAG, "onCreate");
        super.onCreate(savedInstanceState);
    }

    @Override
    public void onResume()
    {
	super.onResume();

	Intent intent = getIntent();
	String action = intent.getAction();
	Log.d(TAG, "onResume: action=" + action);

	if (NfcAdapter.ACTION_NDEF_DISCOVERED.equals(action)) {
	    Log.d(TAG, "onResume - NDEF discovered");
	    Parcelable[] raw = intent.getParcelableArrayExtra(NfcAdapter.EXTRA_NDEF_MESSAGES);
	    if (raw != null) {
		String txt = "NDEF message count: " + raw.length;
		Log.d(TAG, txt);
		NdefMessage[] msgs = new NdefMessage[raw.length];
		for (int i = 0; i < raw.length; i++) {
		    msgs[i] = (NdefMessage) raw[i];
		    NdefRecord rec = msgs[i].getRecords()[0];
		    Log.d(TAG, "MIME type: " + rec.toMimeType());
		    byte[] a = rec.getPayload();
		    Log.d(TAG, "NDEF record: " + byteArrayHex(a));
		    txt += "\nMessage[" + rec.toMimeType() + "]: " +
			byteArrayHex(a);
		}

		TextView textView = new TextView(this);
		textView.setText(txt);
		textView.setMovementMethod(new ScrollingMovementMethod());
		setContentView(textView);
	    }
	}
    }
}
