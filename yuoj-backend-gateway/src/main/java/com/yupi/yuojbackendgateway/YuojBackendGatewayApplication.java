package com.yupi.yuojbackendgateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class YuojBackendGatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(YuojBackendGatewayApplication.class, args);
    }

}
