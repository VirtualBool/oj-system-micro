package com.yupi.yuojbackendjudgeservice.judge;


import com.yupi.yuojbackendmodel.model.entity.QuestionSubmit;

public interface JudgeService {
    /**
     * 判题
     * @param questionSubmitId
     * @return
     */
    QuestionSubmit doJudge(long questionSubmitId);
}
