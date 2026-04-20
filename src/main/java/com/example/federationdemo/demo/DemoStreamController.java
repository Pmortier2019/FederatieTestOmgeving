package com.example.federationdemo.demo;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@RestController
public class DemoStreamController {

    @Value("${federation.base-url}")
    private String baseUrl;

    private final DemoRunner demoRunner;
    private final ObjectMapper objectMapper;

    public DemoStreamController(DemoRunner demoRunner, ObjectMapper objectMapper) {
        this.demoRunner = demoRunner;
        this.objectMapper = objectMapper;
    }

    @GetMapping("/demo")
    public ResponseEntity<String> demo() throws Exception {
        ClassPathResource resource = new ClassPathResource("static/demo.html");
        String html = new String(resource.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(html);
    }

    @GetMapping(value = "/demo/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter stream() {
        SseEmitter emitter = new SseEmitter(300_000L);
        ExecutorService executor = Executors.newSingleThreadExecutor();

        executor.execute(() -> {
            try {
                demoRunner.run(event -> {
                    try {
                        String json = objectMapper.writeValueAsString(event);
                        emitter.send(SseEmitter.event()
                                .name(event.getType().name())
                                .data(json));
                        Thread.sleep(450);
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                });
                emitter.send(SseEmitter.event().name("DONE").data("{}"));
                emitter.complete();
            } catch (Exception e) {
                emitter.completeWithError(e);
            } finally {
                executor.shutdown();
            }
        });

        return emitter;
    }
}
