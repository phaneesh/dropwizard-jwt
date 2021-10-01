package io.dropwizard.auth.jwt.annotation;

import com.google.common.collect.Multimap;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.PARAMETER})
public @interface JwtAuthRequired {

    String[] value() default {};

    JwtAuthParam[] authParams() default {};

}