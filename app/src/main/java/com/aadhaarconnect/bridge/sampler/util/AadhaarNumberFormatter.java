package com.aadhaarconnect.bridge.sampler.util;

import android.text.TextUtils;

public class AadhaarNumberFormatter {
	public static String formatWithSpaces(String aadhaarNumber) {
		if(!TextUtils.isEmpty(aadhaarNumber)) {
			return aadhaarNumber.trim().replace(" ", "").replaceAll("(.{4})(?!$)", "$1 ");
		}
		return aadhaarNumber;
	}
	
	public static String formatWithoutSpaces(String aadhaarNumber) {
		return aadhaarNumber.trim().replace(" ", "");
	}
}
