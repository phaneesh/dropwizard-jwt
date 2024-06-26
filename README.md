# Dropwizard JWT Bundle [![Travis build status](https://travis-ci.org/phaneesh/dropwizard-jwt.svg?branch=master)](https://travis-ci.org/phaneesh/dropwizard-jwt)

This bundle enables one to enable JWT authentication and authorization for all resources
This bundle compiles only on Java 17.

## Features
* Simple to use 
* Supports JWT claims model
 
## Dependencies
* [jose4j](https://bitbucket.org/b_c/jose4j)

### Build instructions
  - Clone the source:

        git clone github.com/phaneesh/dropwizard-jwt

  - Build

        mvn install

### Maven Dependency
Use the following repository:
```xml
<repository>
    <id>clojars</id>
    <name>Clojars repository</name>
    <url>https://clojars.org/repo</url>
</repository>
```
Use the following maven dependency:
```xml
<dependency>
    <groupId>>io.raven.dropwizard.auth</groupId>
    <artifactId>dropwizard-jwt</artifactId>
    <version>3.0.7-1</version>
</dependency>
```

Contributors
------------
* [@phaneeshn](https://twitter.com/phaneeshn)

LICENSE
-------

Copyright 2016 Phaneesh Nagaraja <phaneesh.n@gmail.com>.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.