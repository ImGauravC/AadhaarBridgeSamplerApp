package com.aadhaarconnect.bridge.sampler;

import android.app.Activity;
import android.app.Fragment;
import android.os.Bundle;
import android.text.Html;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TextView;

import com.aadhaarconnect.bridge.capture.model.auth.AuthCaptureData;
import com.aadhaarconnect.bridge.gateway.model.AuthResponse;
import com.aadhaarconnect.bridge.sampler.util.AadhaarNumberFormatter;
import com.google.gson.Gson;
import com.support.android.designlibdemo.R;

public class AuthDisplayFragment extends Fragment implements Constants {
	private ResultActivity resultActivity;
	private AuthResponse authResponse;
	private AuthCaptureData authCaptureData;

    public static AuthDisplayFragment newInstance() {
        Bundle args = new Bundle();

        AuthDisplayFragment fragment = new AuthDisplayFragment();

        return fragment;
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
    }


	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container,
			Bundle savedInstanceState) {
		View view = inflater.inflate(R.layout.auth_result, null);

        authCaptureData = new Gson().fromJson(getActivity().getIntent().getStringExtra(AUTHCAPTUREDATA), AuthCaptureData.class);
        authResponse = new Gson().fromJson(getActivity().getIntent().getStringExtra(AUTHRESPONSE), AuthResponse.class);

		TextView msgTextView = (TextView) view.findViewById(R.id.textViewMsg);
		TextView authRefcode = (TextView) view.findViewById(R.id.textViewAadhaarRefCode);
		Button verifyOtherButton = (Button) view.findViewById(R.id.buttonVerifyOther);
        ImageView verifyStatusImageView = (ImageView) view.findViewById(R.id.imageView1);

		String s = "";

        if(authResponse.isSuccess()) {
            s = String.format(getString(R.string.auth_success_text), AadhaarNumberFormatter.formatWithSpaces(authCaptureData.getAadhaar()));
        } else {
            StringBuilder sb =
                    new StringBuilder()
                            .append(String.format(getString(R.string.auth_fail_text), AadhaarNumberFormatter.formatWithSpaces(authCaptureData.getAadhaar())))
                            .append("\nFailure code is : ")
                            .append(authResponse.getStatusCode());
            s = sb.toString();
            verifyStatusImageView.setImageResource(R.drawable.not_verified);
        }

        msgTextView.setText(Html.fromHtml(s));
		authRefcode.setText(authResponse.getReferenceCode());
		
		verifyOtherButton.setOnClickListener(new View.OnClickListener() {

			@Override
			public void onClick(View v) {
				getActivity().onBackPressed();
			}
		});
		return view;
	}

	@Override
	public void onAttach(Activity activity) {
		resultActivity = (ResultActivity) activity;
		super.onAttach(activity);
	}
}
