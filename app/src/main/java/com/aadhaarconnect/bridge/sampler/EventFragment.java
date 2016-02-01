package com.aadhaarconnect.bridge.sampler;

import android.app.ProgressDialog;
import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.view.View;

import com.support.android.designlibdemo.R;

import de.greenrobot.event.EventBus;

public class EventFragment extends Fragment {

    @Override
    public void onResume() {
        super.onResume();
        EventBus.getDefault().registerSticky(this);
    }

    @Override
    public void onPause() {
        super.onPause();
        EventBus.getDefault().unregister(this);
    }

    private ProgressDialog progressDialog;

    @Override
    public void onViewCreated(View view, Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        setUpProgressDialog();
    }

    @Override
    public void setUserVisibleHint(boolean isVisibleToUser) {
        super.setUserVisibleHint(isVisibleToUser);
        if (isVisibleToUser) {
            setUpProgressDialog();
        }
    }

    public ProgressDialog getProgressDialog() {
        if (progressDialog == null) {
            setUpProgressDialog();
        }
        return progressDialog;
    }

    private void setUpProgressDialog() {
        progressDialog = new ProgressDialog(getActivity());
        progressDialog.setCancelable(true);
        progressDialog.setMessage(getString(R.string.progress_message));
    }

    public void makeProgressDialogCancelable() {
        progressDialog.setCancelable(true);
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
