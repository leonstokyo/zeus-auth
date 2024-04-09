package jp.tokyo.leon.zeus.auth.controller;

import jp.tokyo.leon.zeus.common.api.ResponseResult;
import jp.tokyo.leon.zeus.user.api.dto.ZeusUserDTO;
import jp.tokyo.leon.zeus.user.feign.client.ZeusUserFeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author leon
 * @date 2024/4/2 22:26
 */
@RestController
public class HelloController {

    private final ZeusUserFeignClient zeusUserFeignClient;

    public HelloController(ZeusUserFeignClient zeusUserFeignClient) {
        this.zeusUserFeignClient = zeusUserFeignClient;
    }

    @GetMapping("/auth/hello")
    public String helloAuth() {
        ResponseResult<ZeusUserDTO> leon = zeusUserFeignClient.getUserByUsername("leon");
        return leon.toString();
    }
}
