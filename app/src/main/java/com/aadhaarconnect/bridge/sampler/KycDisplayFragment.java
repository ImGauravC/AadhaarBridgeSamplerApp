package com.aadhaarconnect.bridge.sampler;

import android.app.Activity;
import android.app.Fragment;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TextView;

import com.aadhaarconnect.bridge.capture.model.kyc.KycCaptureData;
import com.aadhaarconnect.bridge.gateway.model.Kyc;
import com.aadhaarconnect.bridge.gateway.model.KycResponse;
import com.aadhaarconnect.bridge.gateway.model.PoaType;
import com.aadhaarconnect.bridge.sampler.util.AadhaarNumberFormatter;
import com.aadhaarconnect.bridge.sampler.util.GsonSerializerUtil;
import com.support.android.designlibdemo.R;

public class KycDisplayFragment extends Fragment implements Constants {
	
	private ResultActivity resultActivity;
	private KycCaptureData kycCaptureData;
	private KycResponse response;

    public static KycDisplayFragment newInstance() {
        Bundle args = new Bundle();

        KycDisplayFragment fragment = new KycDisplayFragment();

        return fragment;
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
    }


	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container,
			Bundle savedInstanceState) {
		View view = inflater.inflate(R.layout.kyc_display, null);

        kycCaptureData = GsonSerializerUtil.unmarshal(getActivity().getIntent().getStringExtra(KYCCAPTUREDATA), KycCaptureData.class);
        response = GsonSerializerUtil.unmarshal(getActivity().getIntent().getStringExtra(KYCRESPONSE), KycResponse.class);


		TextView name = (TextView) view.findViewById(R.id.name);
		TextView gender = (TextView) view.findViewById(R.id.gender);
		TextView dob = (TextView) view.findViewById(R.id.dob);
		TextView phone = (TextView) view.findViewById(R.id.phone);
		TextView email = (TextView) view.findViewById(R.id.email);
		TextView aadhaarNo = (TextView) view.findViewById(R.id.aadharNo);
		TextView address = (TextView) view.findViewById(R.id.address);
		
		Button verifyOtherButton = (Button) view.findViewById(R.id.buttonVerifyOther);
		ImageView photoView = (ImageView) view.findViewById(R.id.user_image);


		//set the value
		Kyc aadhaarKycData = response.getKyc();
		
		byte[] photo = response.getKyc().getPhoto();
        Bitmap bm = BitmapFactory.decodeByteArray(photo, 0, photo.length);
        photoView.setImageBitmap(bm);
        
        name.setText(aadhaarKycData.getPoi().getName());
		gender.setText(aadhaarKycData.getPoi().getGender().name());
		dob.setText(aadhaarKycData.getPoi().getDob());
		
		String phoneString = "-";
		if(!TextUtils.isEmpty(aadhaarKycData.getPoi().getPhone())) {
			phoneString = aadhaarKycData.getPoi().getPhone();
		}
		
		phone.setText(phoneString);
		
		String emailString = "-";
		if(!TextUtils.isEmpty(aadhaarKycData.getPoi().getEmail())) {
			emailString = aadhaarKycData.getPoi().getEmail();
		}
		
		email.setText(emailString);
		
		aadhaarNo.setText(AadhaarNumberFormatter.formatWithSpaces(response.getAadhaarId()));
		address.setText(buildAddress(aadhaarKycData.getPoa()));
		
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
	
    private String buildAddress(PoaType poa) {
        String s = "";
        if (!TextUtils.isEmpty(poa.getCo())) s+= poa.getCo() + ", "; 
        if (!TextUtils.isEmpty(poa.getHouse())) s+= poa.getHouse() + ", "; 
        
        if (!TextUtils.isEmpty(poa.getLm())) s+= poa.getLm() + ", ";
        if (!TextUtils.isEmpty(poa.getLc())) s+= poa.getLc() + ", ";
        if (!TextUtils.isEmpty(poa.getStreet())) s+= poa.getStreet() + ", ";
        
        if (!TextUtils.isEmpty(poa.getVtc())) s+= poa.getVtc() + ", ";
        
        if ( ! poa.getVtc().equalsIgnoreCase(poa.getSubdist())) {
            if (!TextUtils.isEmpty(poa.getSubdist())) s+= poa.getSubdist() + ", ";
        }
        if (!TextUtils.isEmpty(poa.getDist())) s+= poa.getDist() + ", ";
        if (!TextUtils.isEmpty(poa.getState())) s+= poa.getState() + ", ";
        if (!TextUtils.isEmpty(poa.getPc())) s+= poa.getPc();
        
        return s;
    }
}
