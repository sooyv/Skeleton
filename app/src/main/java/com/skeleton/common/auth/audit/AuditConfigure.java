package com.skeleton.common.auth.audit;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.data.mongodb.config.EnableMongoAuditing;

@Configuration
@EnableMongoAuditing
public class AuditConfigure {
    @Bean
    public AuditorAware<String> baseAuditorProvider(){
        return new BaseAuditorAware();
    }
}
