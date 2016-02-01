package com.aadhaarconnect.bridge.sampler;

import android.app.ProgressDialog;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;

import de.greenrobot.event.EventBus;

public class EventActivity extends AppCompatActivity {

    private ProgressDialog progressDialog;

    @Override
    protected void onCreate(Bundle arg0) {
        super.onCreate(arg0);
        setUpProgressDialog();
    }

    @Override
    protected void onResume() {
        super.onResume();
        EventBus.getDefault().registerSticky(this);
    }

    @Override
    protected void onPause() {
        super.onPause();
        EventBus.getDefault().unregister(this);
    }

    public ProgressDialog getProgressDialog() {
        if (progressDialog == null) {
            setUpProgressDialog();
        }
        return progressDialog;
    }

    private void setUpProgressDialog() {
        progressDialog = new ProgressDialog(this);
    }

    public void setProgressMessage(int stringResid) {
        progressDialog.setMessage(getString(stringResid));
    }

    public void showProgressDialog() {
        if (!progressDialog.isShowing()) {
            progressDialog.show();
        }
    }

    public void dismissProgressDialog() {
        if (progressDialog.isShowing()) {
            progressDialog.dismiss();
        }
    }
}