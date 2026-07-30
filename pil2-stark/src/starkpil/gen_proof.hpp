#include "starks.hpp"
#include "pil2_dump.hpp"
#include "starks_api_internal.hpp"

void calculateWitnessExpr(SetupCtx& setupCtx, StepsParams& params, ExpressionsCtx &expressionsCtx) {
    uint64_t nWitnessHints = setupCtx.expressionsBin.getNumberHintIdsByName("witness_calc");
    if(nWitnessHints > 0) {
        std::vector<uint64_t> witnessHints(nWitnessHints);
        setupCtx.expressionsBin.getHintIdsByName(witnessHints.data(), "witness_calc");
        std::vector<std::string> hintFieldDest(nWitnessHints);
        std::vector<std::string> hintField(nWitnessHints);
        std::vector<HintFieldOptions> hintOptions(nWitnessHints);
        for(uint64_t i = 0; i < nWitnessHints; i++) {
            hintFieldDest[i] = "reference";
            hintField[i] = "expression";
            HintFieldOptions options;
            hintOptions[i] = options;
        }

        calculateExpr(setupCtx, params, expressionsCtx, nWitnessHints, witnessHints.data(), hintFieldDest.data(), hintField.data(), hintOptions.data());
    }
}


void calculateWitnessSTD(SetupCtx& setupCtx, StepsParams& params, ExpressionsCtx &expressionsCtx, bool prod) {
    std::string name = prod ? "gprod_col" : "gsum_col";
    if(setupCtx.expressionsBin.getNumberHintIdsByName(name) == 0) return;
    uint64_t hint[1];
    setupCtx.expressionsBin.getHintIdsByName(hint, name);

    uint64_t nImHints = setupCtx.expressionsBin.getNumberHintIdsByName("im_col");
    uint64_t nImHintsAirVals = setupCtx.expressionsBin.getNumberHintIdsByName("im_airval");
    uint64_t nImTotalHints = nImHints + nImHintsAirVals;
    if(nImTotalHints > 0) {
        std::vector<uint64_t> imHints(nImHints + nImHintsAirVals);
        setupCtx.expressionsBin.getHintIdsByName(imHints.data(), "im_col");
        setupCtx.expressionsBin.getHintIdsByName(&imHints[nImHints], "im_airval");
        std::vector<std::string> hintFieldDest(nImTotalHints);
        std::vector<std::string> hintField1(nImTotalHints);
        std::vector<std::string> hintField2(nImTotalHints);
        std::vector<HintFieldOptions> hintOptions1(nImTotalHints);
        std::vector<HintFieldOptions> hintOptions2(nImTotalHints);
        for(uint64_t i = 0; i < nImTotalHints; i++) {
            hintFieldDest[i] = "reference";
            hintField1[i] = "numerator";
            hintField2[i] = "denominator";
            HintFieldOptions options1;
            HintFieldOptions options2;
            options2.inverse = true;
            hintOptions1[i] = options1;
            hintOptions2[i] = options2;
        }

        multiplyHintFields(setupCtx, params, expressionsCtx, nImTotalHints, imHints.data(), hintFieldDest.data(), hintField1.data(), hintField2.data(), hintOptions1.data(), hintOptions2.data());
        
    }

    HintFieldOptions options1;
    HintFieldOptions options2;
    options2.inverse = true;

    std::string hintFieldNameAirgroupVal = setupCtx.starkInfo.airgroupValuesMap.size() > 0 ? "result" : "";

    accMulHintFields(setupCtx, params, expressionsCtx, hint[0], "reference", hintFieldNameAirgroupVal, "numerator_air", "denominator_air", options1, options2, !prod);
    updateAirgroupValue(setupCtx, params, hint[0], hintFieldNameAirgroupVal, "numerator_direct", "denominator_direct", options1, options2, !prod);
}

void genProof(SetupCtx& setupCtx, uint64_t airgroupId, uint64_t airId, uint64_t instanceId, StepsParams& params, Goldilocks::Element *globalChallenge, uint64_t *proofBuffer, std::string proofFile, bool recursive = false) {
    TimerStart(STARK_PROOF);
    NTT_Goldilocks ntt(1 << setupCtx.starkInfo.starkStruct.nBits);
    NTT_Goldilocks nttExtended(1 << setupCtx.starkInfo.starkStruct.nBitsExt);

    ProverHelpers proverHelpers(setupCtx.starkInfo, false);

    FRIProof<Goldilocks::Element> proof(setupCtx.starkInfo, airgroupId, airId, instanceId);
    
    Starks<Goldilocks::Element> starks(setupCtx, params.pConstPolsExtendedTreeAddress, params.pCustomCommitsFixed, false, false);

    // One dump-name prefix per AIR instance so multi-instance proves never
    // overwrite each other's files; the stage-1 trace and publics let a
    // consumer replay the whole pipeline from the same witness.
    std::string dumpPrefix = pil2DumpTag() + "ag" + std::to_string(airgroupId) + "_air" +
        std::to_string(airId) + "_inst" + std::to_string(instanceId) + "_";
    if (std::getenv("PIL2_DUMP_DIR")) {
        if (setupCtx.starkInfo.mapSectionsN.count("cm1")) {
            pil2DumpU64(dumpPrefix + "trace", params.trace,
                        setupCtx.starkInfo.mapSectionsN["cm1"] *
                            (1ULL << setupCtx.starkInfo.starkStruct.nBits));
        }
        pil2DumpU64(dumpPrefix + "publics", params.publicInputs,
                    setupCtx.starkInfo.nPublics);
        std::string mp = std::string(std::getenv("PIL2_DUMP_DIR")) + "/" + dumpPrefix + "meta.json";
        FILE* mf = fopen(mp.c_str(), "w");
        if (mf) {
            fprintf(mf, "{\n  \"airgroup_id\": %lu,\n  \"air_id\": %lu,\n  \"instance_id\": %lu,\n"
                        "  \"n_bits\": %lu,\n  \"n_bits_ext\": %lu\n}\n",
                    airgroupId, airId, instanceId,
                    setupCtx.starkInfo.starkStruct.nBits,
                    setupCtx.starkInfo.starkStruct.nBitsExt);
            fclose(mf);
        }
    }
    
    ExpressionsPack expressionsCtx(setupCtx, &proverHelpers);

    TranscriptGL transcript(setupCtx.starkInfo.starkStruct.transcriptArity, setupCtx.starkInfo.starkStruct.merkleTreeCustom);

    TimerStart(STARK_STEP_0);
    for (uint64_t i = 0; i < setupCtx.starkInfo.customCommits.size(); i++) {
        if(setupCtx.starkInfo.customCommits[i].stageWidths[0] != 0) {
            uint64_t pos = setupCtx.starkInfo.nStages + 2 + i;
            starks.treesGL[pos]->getRoot(&proof.proof.roots[setupCtx.starkInfo.nStages + 1 + i][0]);
            starks.treesGL[pos]->getLevel(&proof.proof.last_levels[setupCtx.starkInfo.nStages + 2 + i][0]);
        }
    }

    starks.treesGL[setupCtx.starkInfo.nStages + 1]->getLevel(&proof.proof.last_levels[setupCtx.starkInfo.nStages + 1][0]);

    if(recursive) {
        Goldilocks::Element verkey[HASH_SIZE];
        starks.treesGL[setupCtx.starkInfo.nStages + 1]->getRoot(verkey);
        pil2DumpAppendU64(dumpPrefix + "absorbs", &verkey[0], HASH_SIZE);
    starks.addTranscript(transcript, &verkey[0], HASH_SIZE);
        if(setupCtx.starkInfo.nPublics > 0) {
            if(!setupCtx.starkInfo.starkStruct.hashCommits) {
                pil2DumpAppendU64(dumpPrefix + "absorbs", &params.publicInputs[0], setupCtx.starkInfo.nPublics);
    starks.addTranscriptGL(transcript, &params.publicInputs[0], setupCtx.starkInfo.nPublics);
            } else {
                Goldilocks::Element hash[HASH_SIZE];
                starks.calculateHash(hash, &params.publicInputs[0], setupCtx.starkInfo.nPublics);
                pil2DumpAppendU64(dumpPrefix + "absorbs", hash, HASH_SIZE);
    starks.addTranscript(transcript, hash, HASH_SIZE);
            }
        }
    } else {
        pil2DumpAppendU64(dumpPrefix + "absorbs", globalChallenge, FIELD_EXTENSION);
    starks.addTranscript(transcript, globalChallenge, FIELD_EXTENSION);
        pil2DumpU64(dumpPrefix + "global_challenge", globalChallenge, FIELD_EXTENSION);
    }

    TimerStopAndLog(STARK_STEP_0);

    TimerStart(STARK_STEP_1);
    if (setupCtx.starkInfo.mapSectionsN.count("cm1")) {
        pil2DumpU64(dumpPrefix + "trace", params.trace,
                    setupCtx.starkInfo.mapSectionsN["cm1"] *
                        (1ULL << setupCtx.starkInfo.starkStruct.nBits));
    }
    calculateWitnessExpr(setupCtx, params, expressionsCtx);
    if(recursive) {
        starks.commitStage(1, params.trace, params.aux_trace, proof, ntt);
        pil2DumpAppendU64(dumpPrefix + "absorbs", &proof.proof.roots[0][0], HASH_SIZE);
    starks.addTranscript(transcript, &proof.proof.roots[0][0], HASH_SIZE);
    } else {
        starks.commitStage(1, params.trace, params.aux_trace, proof, ntt, &params.aux_trace[setupCtx.starkInfo.mapOffsets[std::make_pair("buff_helper_fft_1", false)]]);
    }
    pil2DumpU64(dumpPrefix + "root1", &proof.proof.roots[0][0], HASH_SIZE);
    if (setupCtx.starkInfo.mapSectionsN.count("cm1")) {
        pil2DumpU64(dumpPrefix + "trace_post", params.trace,
                    setupCtx.starkInfo.mapSectionsN["cm1"] *
                        (1ULL << setupCtx.starkInfo.starkStruct.nBits));
    }
    if (setupCtx.starkInfo.mapOffsets.count(std::make_pair(std::string("cm1"), true))) {
        pil2DumpU64(dumpPrefix + "cm1_ext",
                    &params.aux_trace[setupCtx.starkInfo.mapOffsets[std::make_pair(std::string("cm1"), true)]],
                    setupCtx.starkInfo.mapSectionsN["cm1"] *
                        (1ULL << setupCtx.starkInfo.starkStruct.nBitsExt));
    }
    TimerStopAndLog(STARK_STEP_1);

    TimerStart(STARK_STEP_2);
    TimerStart(STARK_CALCULATE_WITNESS_STD);
    for (uint64_t i = 0; i < setupCtx.starkInfo.challengesMap.size(); i++) {
        if(setupCtx.starkInfo.challengesMap[i].stage == 2) {
            starks.getChallenge(transcript, params.challenges[i * FIELD_EXTENSION]);
        }
    }

    calculateWitnessSTD(setupCtx, params, expressionsCtx, true);
    calculateWitnessSTD(setupCtx, params, expressionsCtx, false);
    TimerStopAndLog(STARK_CALCULATE_WITNESS_STD);
    
    TimerStart(CALCULATE_IM_POLS);
    starks.calculateImPolsExpressions(2, params, expressionsCtx);
    TimerStopAndLog(CALCULATE_IM_POLS);

    TimerStart(STARK_COMMIT_STAGE_2);
    if (recursive) {
        starks.commitStage(2, nullptr, params.aux_trace, proof, ntt);
    } else {
        starks.commitStage(2, nullptr, params.aux_trace, proof, ntt, &params.aux_trace[setupCtx.starkInfo.mapOffsets[std::make_pair("buff_helper_fft_2", false)]]);
    }
    TimerStopAndLog(STARK_COMMIT_STAGE_2);
    pil2DumpU64(dumpPrefix + "root2", &proof.proof.roots[1][0], HASH_SIZE);
    {
        auto k2 = std::make_pair(std::string("cm2"), false);
        if (setupCtx.starkInfo.mapOffsets.count(k2) && setupCtx.starkInfo.mapSectionsN.count("cm2")) {
            pil2DumpU64(dumpPrefix + "cm2_base", &params.aux_trace[setupCtx.starkInfo.mapOffsets[k2]],
                        (1ULL << setupCtx.starkInfo.starkStruct.nBits) *
                            setupCtx.starkInfo.mapSectionsN["cm2"]);
        }
    }
    pil2DumpAppendU64(dumpPrefix + "absorbs", &proof.proof.roots[1][0], HASH_SIZE);
    starks.addTranscript(transcript, &proof.proof.roots[1][0], HASH_SIZE);

    uint64_t a = 0;
    for(uint64_t i = 0; i < setupCtx.starkInfo.airValuesMap.size(); i++) {
        if(setupCtx.starkInfo.airValuesMap[i].stage == 1) a++;
        if(setupCtx.starkInfo.airValuesMap[i].stage == 2) {
            pil2DumpAppendU64(dumpPrefix + "absorbs", &params.airValues[a], FIELD_EXTENSION);
    starks.addTranscript(transcript, &params.airValues[a], FIELD_EXTENSION);
            a += 3;
        }
    }

    TimerStopAndLog(STARK_STEP_2);

    TimerStart(STARK_STEP_Q);

    for (uint64_t i = 0; i < setupCtx.starkInfo.challengesMap.size(); i++)
    {
        if(setupCtx.starkInfo.challengesMap[i].stage == setupCtx.starkInfo.nStages + 1) {
            starks.getChallenge(transcript, params.challenges[i * FIELD_EXTENSION]);
        }
    }

    TimerStart(STARK_CALCULATE_QUOTIENT_POLYNOMIAL);
    starks.calculateQuotientPolynomial(params, expressionsCtx);
    TimerStopAndLog(STARK_CALCULATE_QUOTIENT_POLYNOMIAL);
    if (setupCtx.starkInfo.mapOffsets.count(std::make_pair(std::string("q"), true))) {
        pil2DumpU64(dumpPrefix + "q_ext",
                    &params.aux_trace[setupCtx.starkInfo.mapOffsets[std::make_pair(std::string("q"), true)]],
                    (1ULL << setupCtx.starkInfo.starkStruct.nBitsExt) * setupCtx.starkInfo.qDim);
    }
    TimerStart(STARK_COMMIT_QUOTIENT_POLYNOMIAL);
    if (recursive) {
        starks.commitStage(setupCtx.starkInfo.nStages + 1, nullptr, params.aux_trace, proof, nttExtended);
    } else {
        starks.commitStage(setupCtx.starkInfo.nStages + 1, nullptr, params.aux_trace, proof, nttExtended, &params.aux_trace[setupCtx.starkInfo.mapOffsets[std::make_pair("buff_helper_fft_3", false)]]);
    }
    TimerStopAndLog(STARK_COMMIT_QUOTIENT_POLYNOMIAL);
    {
        std::string qName = "cm" + std::to_string(setupCtx.starkInfo.nStages + 1);
        auto qKey = std::make_pair(qName, true);
        if (setupCtx.starkInfo.mapOffsets.count(qKey) && setupCtx.starkInfo.mapSectionsN.count(qName)) {
            uint64_t nExtQ = 1ULL << setupCtx.starkInfo.starkStruct.nBitsExt;
            pil2DumpU64(dumpPrefix + "quotient_cm", &params.aux_trace[setupCtx.starkInfo.mapOffsets[qKey]],
                        nExtQ * setupCtx.starkInfo.mapSectionsN[qName]);
        }
    }

    pil2DumpU64(dumpPrefix + "rootQ", &proof.proof.roots[setupCtx.starkInfo.nStages][0], HASH_SIZE);
    pil2DumpAppendU64(dumpPrefix + "absorbs", &proof.proof.roots[setupCtx.starkInfo.nStages][0], HASH_SIZE);
    starks.addTranscript(transcript, &proof.proof.roots[setupCtx.starkInfo.nStages][0], HASH_SIZE);
    TimerStopAndLog(STARK_STEP_Q);

    TimerStart(STARK_STEP_EVALS);

    uint64_t xiChallengeIndex = 0;
    for (uint64_t i = 0; i < setupCtx.starkInfo.challengesMap.size(); i++)
    {
        if(setupCtx.starkInfo.challengesMap[i].stage == setupCtx.starkInfo.nStages + 2) {
            if(setupCtx.starkInfo.challengesMap[i].stageId == 0) xiChallengeIndex = i;
            starks.getChallenge(transcript, params.challenges[i * FIELD_EXTENSION]);
        }
    }

    Goldilocks::Element *xiChallenge = &params.challenges[xiChallengeIndex * FIELD_EXTENSION];
    Goldilocks::Element* LEv = &params.aux_trace[setupCtx.starkInfo.mapOffsets[make_pair("lev", false)]];

    for(uint64_t i = 0; i < setupCtx.starkInfo.openingPoints.size(); i += 4) {
        std::vector<int64_t> openingPoints;
        for(uint64_t j = 0; j < 4; ++j) {
            if(i + j < setupCtx.starkInfo.openingPoints.size()) {
                openingPoints.push_back(setupCtx.starkInfo.openingPoints[i + j]);
            }
        }
        starks.computeLEv(xiChallenge, LEv, openingPoints, ntt);
        starks.computeEvals(params ,LEv, proof, openingPoints);
    }
    

    pil2DumpU64(dumpPrefix + "evals", params.evals, setupCtx.starkInfo.evMap.size() * FIELD_EXTENSION);
    if (std::getenv("PIL2_DUMP_DIR")) {
        uint64_t nExtD = 1ULL << setupCtx.starkInfo.starkStruct.nBitsExt;
        for (uint64_t st = 2; st <= setupCtx.starkInfo.nStages; st++) {
            std::string sec = "cm" + std::to_string(st);
            auto k = std::make_pair(sec, true);
            if (setupCtx.starkInfo.mapOffsets.count(k) && setupCtx.starkInfo.mapSectionsN.count(sec)) {
                pil2DumpU64(dumpPrefix + sec + "_ext", &params.aux_trace[setupCtx.starkInfo.mapOffsets[k]],
                            nExtD * setupCtx.starkInfo.mapSectionsN[sec]);
            }
        }
        pil2DumpU64(dumpPrefix + "const_ext",
                    starks.treesGL[setupCtx.starkInfo.nStages + 1]->source,
                    nExtD * setupCtx.starkInfo.nConstants);
        for (uint64_t i = 0; i < setupCtx.starkInfo.customCommits.size(); i++) {
            std::string sec = setupCtx.starkInfo.customCommits[i].name + "0";
            if (setupCtx.starkInfo.mapSectionsN.count(sec)) {
                pil2DumpU64(dumpPrefix + "custom" + std::to_string(i) + "_ext",
                            starks.treesGL[setupCtx.starkInfo.nStages + 2 + i]->source,
                            nExtD * setupCtx.starkInfo.mapSectionsN[sec]);
            }
        }
    }
    if(!setupCtx.starkInfo.starkStruct.hashCommits) {
        pil2DumpAppendU64(dumpPrefix + "absorbs", params.evals, setupCtx.starkInfo.evMap.size() * FIELD_EXTENSION);
    starks.addTranscriptGL(transcript, params.evals, setupCtx.starkInfo.evMap.size() * FIELD_EXTENSION);
    } else {
        Goldilocks::Element hash[HASH_SIZE];
        starks.calculateHash(hash, params.evals, setupCtx.starkInfo.evMap.size() * FIELD_EXTENSION);
        pil2DumpAppendU64(dumpPrefix + "absorbs", hash, HASH_SIZE);
    starks.addTranscript(transcript, hash, HASH_SIZE);
    }
    // Challenges for FRI polynomial
    for (uint64_t i = 0; i < setupCtx.starkInfo.challengesMap.size(); i++)
    {
        if(setupCtx.starkInfo.challengesMap[i].stage == setupCtx.starkInfo.nStages + 3) {
            starks.getChallenge(transcript, params.challenges[i * FIELD_EXTENSION]);
        }
    }

    TimerStopAndLog(STARK_STEP_EVALS);

    //--------------------------------
    // 6. Compute FRI
    //--------------------------------
    TimerStart(STARK_STEP_FRI);

    TimerStart(COMPUTE_FRI_POLYNOMIAL);
    starks.calculateFRIPolynomial(params, expressionsCtx);
    TimerStopAndLog(COMPUTE_FRI_POLYNOMIAL);

    Goldilocks::Element challenge[FIELD_EXTENSION];
    Goldilocks::Element *friPol = &params.aux_trace[setupCtx.starkInfo.mapOffsets[std::make_pair("f", true)]];
    pil2DumpU64(dumpPrefix + "deep_f", friPol,
                (1ULL << setupCtx.starkInfo.starkStruct.steps[0].nBits) * FIELD_EXTENSION);
    
    TimerStart(STARK_FRI_FOLDING);
    uint64_t nBitsExt =  setupCtx.starkInfo.starkStruct.steps[0].nBits;
    for (uint64_t step = 0; step < setupCtx.starkInfo.starkStruct.steps.size(); step++)
    {   
        uint64_t currentBits = setupCtx.starkInfo.starkStruct.steps[step].nBits;
        uint64_t prevBits = step == 0 ? currentBits : setupCtx.starkInfo.starkStruct.steps[step - 1].nBits;
        FRI<Goldilocks::Element>::fold(step, friPol, challenge, nBitsExt, prevBits, currentBits);
        pil2DumpU64(dumpPrefix + "fri_layer" + std::to_string(step), friPol,
                    (1ULL << currentBits) * FIELD_EXTENSION);
        if (step < setupCtx.starkInfo.starkStruct.steps.size() - 1)
        {
            FRI<Goldilocks::Element>::merkelize(step, proof, friPol, starks.treesFRI[step], currentBits, setupCtx.starkInfo.starkStruct.steps[step + 1].nBits);
            pil2DumpAppendU64(dumpPrefix + "absorbs", &proof.proof.fri.treesFRI[step].root[0], HASH_SIZE);
    starks.addTranscript(transcript, &proof.proof.fri.treesFRI[step].root[0], HASH_SIZE);
        }
        else
        {
            if(!setupCtx.starkInfo.starkStruct.hashCommits) {
                pil2DumpAppendU64(dumpPrefix + "absorbs", friPol, (1 << setupCtx.starkInfo.starkStruct.steps[step].nBits) * FIELD_EXTENSION);
    starks.addTranscriptGL(transcript, friPol, (1 << setupCtx.starkInfo.starkStruct.steps[step].nBits) * FIELD_EXTENSION);
            } else {
                Goldilocks::Element hash[HASH_SIZE];
                starks.calculateHash(hash, friPol, (1 << setupCtx.starkInfo.starkStruct.steps[step].nBits) * FIELD_EXTENSION);
                pil2DumpAppendU64(dumpPrefix + "absorbs", hash, HASH_SIZE);
    starks.addTranscript(transcript, hash, HASH_SIZE);
            } 
            
        }
        starks.getChallenge(transcript, *challenge);
        pil2DumpU64(dumpPrefix + "fri_beta" + std::to_string(step), challenge,
                    FIELD_EXTENSION);
    }
    pil2DumpU64(dumpPrefix + "airvalues", params.airValues,
                setupCtx.starkInfo.airValuesSize);
    pil2DumpU64(dumpPrefix + "airgroupvalues", params.airgroupValues,
                setupCtx.starkInfo.airgroupValuesSize);
    pil2DumpU64(dumpPrefix + "proofvalues", params.proofValues,
                setupCtx.starkInfo.proofValuesSize);
    pil2DumpU64(dumpPrefix + "challenges", params.challenges,
                setupCtx.starkInfo.challengesMap.size() * FIELD_EXTENSION);
    TimerStopAndLog(STARK_FRI_FOLDING);
    TimerStart(STARK_FRI_QUERIES);

    uint64_t friQueries[setupCtx.starkInfo.starkStruct.nQueries];

    uint64_t nonce;
    runGrinding(nonce, (uint64_t *)challenge, setupCtx.starkInfo.starkStruct.powBits);

    TranscriptGL transcriptPermutation(setupCtx.starkInfo.starkStruct.transcriptArity, setupCtx.starkInfo.starkStruct.merkleTreeCustom);
    pil2DumpAppendU64(dumpPrefix + "absorbs", challenge, FIELD_EXTENSION);
    starks.addTranscriptGL(transcriptPermutation, challenge, FIELD_EXTENSION);
    pil2DumpAppendU64(dumpPrefix + "absorbs", (Goldilocks::Element *)&nonce, 1);
    starks.addTranscriptGL(transcriptPermutation, (Goldilocks::Element *)&nonce, 1);
    transcriptPermutation.getPermutations(friQueries, setupCtx.starkInfo.starkStruct.nQueries, setupCtx.starkInfo.starkStruct.steps[0].nBits);

    uint64_t nTrees = setupCtx.starkInfo.nStages + setupCtx.starkInfo.customCommits.size() + 2;
    FRI<Goldilocks::Element>::proveQueries(friQueries, setupCtx.starkInfo.starkStruct.nQueries, proof, starks.treesGL, nTrees);

    for(uint64_t step = 1; step < setupCtx.starkInfo.starkStruct.steps.size(); ++step) {

        FRI<Goldilocks::Element>::proveFRIQueries(friQueries, setupCtx.starkInfo.starkStruct.nQueries, step, setupCtx.starkInfo.starkStruct.steps[step].nBits, proof, starks.treesFRI[step - 1]);
    }

    FRI<Goldilocks::Element>::setFinalPol(proof, friPol, setupCtx.starkInfo.starkStruct.steps[setupCtx.starkInfo.starkStruct.steps.size() - 1].nBits);
    TimerStopAndLog(STARK_FRI_QUERIES);

    TimerStopAndLog(STARK_STEP_FRI);

    proof.proof.setEvals(params.evals);
    proof.proof.setAirgroupValues(params.airgroupValues);
    proof.proof.setAirValues(params.airValues);
    proof.proof.setNonce(nonce);

    proof.proof.proof2pointer(proofBuffer);

    if(!proofFile.empty()) {
        json2file(pointer2json(proofBuffer, setupCtx.starkInfo), proofFile);
    }

    TimerStopAndLog(STARK_PROOF);    
}
