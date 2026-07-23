// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.airwallex.ap2.protocol;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record JsonWebKey(
    String kty,
    String crv,
    String x,
    String y,
    String use,
    List<String> keyOps,
    String alg,
    String kid,
    String x5u,
    List<String> x5c,
    String x5t,
    @JsonProperty("x5t#S256") String x5tS256) {
}