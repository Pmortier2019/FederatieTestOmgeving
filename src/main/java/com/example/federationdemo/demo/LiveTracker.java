package com.example.federationdemo.demo;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

@Component
public class LiveTracker {

    private final List<SseEmitter> emitters = new CopyOnWriteArrayList<>();
    private final ObjectMapper objectMapper;

    public LiveTracker(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public SseEmitter register() {
        SseEmitter emitter = new SseEmitter(600_000L);
        emitters.add(emitter);
        emitter.onCompletion(() -> emitters.remove(emitter));
        emitter.onTimeout(() -> emitters.remove(emitter));
        emitter.onError(e -> emitters.remove(emitter));
        return emitter;
    }

    public void broadcast(DemoEvent event) {
        if (emitters.isEmpty()) return;
        String json;
        try {
            json = objectMapper.writeValueAsString(event);
        } catch (Exception e) {
            return;
        }
        for (SseEmitter emitter : emitters) {
            try {
                emitter.send(SseEmitter.event()
                        .name(event.getType().name())
                        .data(json));
            } catch (Exception ex) {
                emitters.remove(emitter);
            }
        }
    }
}
