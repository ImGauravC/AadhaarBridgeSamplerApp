package com.aadhaarconnect.bridge.sampler.events;

public class CompletionEvent extends BaseEvent {

    private boolean wasEventASuccess = false;
    private String successMsg = "Success";
    private String failureMsg = "Operation Failed";
    private String response;
    private int code;

    public boolean WasEventASuccess() {
        return wasEventASuccess;
    }

    public CompletionEvent setEventASuccess() {
        this.wasEventASuccess = true;
        return this;
    }

    public CompletionEvent setEventAFailure() {
        this.wasEventASuccess = false;
        return this;
    }

    public String getSuccessMsg() {
        return successMsg;
    }

    public CompletionEvent setSuccessMsg(String successMsg) {
        this.successMsg = successMsg;
        return this;
    }

    public String getFailureMsg() {
        return failureMsg;
    }

    public CompletionEvent setFailureMsg(String failureMsg) {
        this.failureMsg = failureMsg;
        return this;
    }

    public int getCode() {
        return code;
    }

    public CompletionEvent setCode(int code) {
        this.code = code;
        return this;
    }

    public String getResponseString() {
        return response;
    }

    public CompletionEvent setResponseString(String response) {
        this.response = response;
        return this;
    }

}