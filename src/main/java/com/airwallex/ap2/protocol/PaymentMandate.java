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

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import java.util.Map;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record PaymentMandate(
    String vct,
    String transactionId,
    Merchant payee,
    Amount paymentAmount,
    PaymentInstrument paymentInstrument,
    Pisp pisp,
    String executionDate,
    Map<String, Object> riskData,
    Long iat,
    Long exp) {

    public static final String VCT = "mandate.payment.1";

    public PaymentMandate {
        if (vct == null) {
            vct = VCT;
        }
    }

    public static PaymentMandate create(
            String transactionId,
            Merchant payee,
            Amount paymentAmount,
            PaymentInstrument paymentInstrument) {
        return new PaymentMandate(
                VCT, transactionId, payee, paymentAmount, paymentInstrument,
                null, null, null, null, null);
    }
}