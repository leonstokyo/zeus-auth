package jp.tokyo.leon.zeus.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

/**
 * @author leon
 */
@EnableDiscoveryClient
@SpringBootApplication
public class ZeusAuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(ZeusAuthApplication.class, args);
    }

}
