package jp.tokyo.leon.zeus.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.context.annotation.ComponentScan;

/**
 * @author leon
 */
@EnableDiscoveryClient
@EnableFeignClients(basePackages = {"jp.tokyo.leon.zeus.user.feign.client"})
@SpringBootApplication
public class ZeusAuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(ZeusAuthApplication.class, args);
    }

}
