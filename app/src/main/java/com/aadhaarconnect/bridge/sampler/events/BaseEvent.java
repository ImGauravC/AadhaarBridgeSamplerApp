package com.aadhaarconnect.bridge.sampler.events;

public class BaseEvent {
    private ABSEvent event;

    public ABSEvent getEvent() {
        return event;
    }

    public BaseEvent setEvent(ABSEvent event) {
        this.event = event;
        return this;
    }
}
