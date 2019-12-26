package com.ken.wms.security.controller;

import com.ken.wms.common.service.Interface.SystemLogService;
import com.ken.wms.common.util.Response;
import com.ken.wms.common.util.ResponseUtil;
import com.ken.wms.exception.SystemLogServiceException;
import com.ken.wms.exception.UserAccountServiceException;
import com.ken.wms.security.service.Interface.AccountService;
import com.ken.wms.security.util.CheckCodeGenerator;
import com.ken.wms.util.MD5;

import org.apache.log4j.Logger;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.imageio.ImageIO;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import java.awt.image.BufferedImage;
import java.io.IOException;
import java.util.Map;

/**
 * 鐢ㄦ埛璐︽埛璇锋眰 Handler
 *
 * @author Ken
 * @since 017/2/26.
 */
@Controller
@RequestMapping("/account")
public class AccountHandler {

    private static Logger log = Logger.getLogger("application");

    @Autowired
    private ResponseUtil responseUtil;
    @Autowired
    private CheckCodeGenerator checkCodeGenerator;
    @Autowired
    private AccountService accountService;
    @Autowired
    private SystemLogService systemLogService;

    private static final String USER_ID = "id";
    private static final String USER_NAME = "userName";
    private static final String USER_PASSWORD = "password";

    /**
     * 鐧婚檰璐︽埛
     *
     * @param user 璐︽埛淇℃伅
     * @return 杩斿洖涓�涓� Map 瀵硅薄锛屽叾涓寘鍚櫥闄嗘搷浣滅殑缁撴灉
     */
    @SuppressWarnings("unchecked")
    @RequestMapping(value = "login", method = RequestMethod.POST)
    public
    @ResponseBody
    Map<String, Object> login(@RequestBody Map<String, Object> user) {
        // 鍒濆鍖� Response
        Response response = responseUtil.newResponseInstance();
        String result = Response.RESPONSE_RESULT_ERROR;
        String errorMsg = "";

        // 鑾峰彇褰撳墠鐨勭敤鎴风殑 Subject锛宻hiro
        Subject currentUser = SecurityUtils.getSubject();

        // 鍒ゆ柇鐢ㄦ埛鏄惁宸茬粡鐧婚檰
        if (currentUser != null && !currentUser.isAuthenticated()) {
            String id = (String) user.get(USER_ID);
            MD5 md = new MD5();
            String password = md.digest((String) user.get(USER_PASSWORD));
            UsernamePasswordToken token = new UsernamePasswordToken(id, password);

            // 鎵ц鐧婚檰鎿嶄綔
            try {
                //浼氳皟鐢╮ealms/UserAuthorizingRealm涓殑doGetAuthenticationInfo鏂规硶
                currentUser.login(token);

                // 璁剧疆鐧婚檰鐘舵�佸苟璁板綍
                Session session = currentUser.getSession();
                session.setAttribute("isAuthenticate", "true");
                Integer userID_integer = (Integer) session.getAttribute("userID");
                String userName = (String) session.getAttribute("userName");
                String accessIP = session.getHost();
                systemLogService.insertAccessRecord(userID_integer, userName, accessIP, SystemLogService.ACCESS_TYPE_LOGIN);

                result = Response.RESPONSE_RESULT_SUCCESS;
            } catch (UnknownAccountException e) {
                errorMsg = "unknownAccount";
            } catch (IncorrectCredentialsException e) {
                errorMsg = "incorrectCredentials";
            } catch (AuthenticationException e) {
                errorMsg = "authenticationError";
            } catch (SystemLogServiceException e) {
                errorMsg = "ServerError";
            }
        } else {
            errorMsg = "already login";
        }

        // 璁剧疆 Response
        response.setResponseResult(result);
        response.setResponseMsg(errorMsg);
        return response.generateResponse();
    }

    /**
     * 娉ㄩ攢璐︽埛
     *
     * @return 杩斿洖涓�涓� Map 瀵硅薄锛岄敭鍊间负 result 鐨勫唴瀹逛唬琛ㄦ敞閿�鎿嶄綔鐨勭粨鏋滐紝鍊间负 success 鎴� error
     */
    @RequestMapping(value = "logout", method = RequestMethod.GET)
    public
    @ResponseBody
    Map<String, Object> logout() {
        // 鍒濆鍖� Response
        Response response = responseUtil.newResponseInstance();

        Subject currentSubject = SecurityUtils.getSubject();
        if (currentSubject != null && currentSubject.isAuthenticated()) {
            // 鎵ц璐︽埛娉ㄩ攢鎿嶄綔
            currentSubject.logout();
            response.setResponseResult(Response.RESPONSE_RESULT_SUCCESS);
        } else {
            response.setResponseResult(Response.RESPONSE_RESULT_ERROR);
            response.setResponseMsg("did not login");
        }

        return response.generateResponse();
    }

    /**
     * 淇敼璐︽埛瀵嗙爜
     *
     * @param passwordInfo 瀵嗙爜淇℃伅
     * @param request      璇锋眰
     * @return 杩斿洖涓�涓� Map 瀵硅薄锛屽叾涓敭鍊间负 result 浠ｈ〃淇敼瀵嗙爜鎿嶄綔鐨勭粨鏋滐紝
     * 鍊间负 success 鎴� error锛涢敭鍊间负 msg 浠ｈ〃闇�瑕佽繑鍥炵粰鐢ㄦ埛鐨勪俊鎭�
     */
    @RequestMapping(value = "passwordModify", method = RequestMethod.POST)
    public
    @ResponseBody
    Map<String, Object> passwordModify(@RequestBody Map<String, Object> passwordInfo,
                                       HttpServletRequest request) {
        //鍒濆鍖� Response
        Response responseContent = responseUtil.newResponseInstance();

        String errorMsg = null;
        String result = Response.RESPONSE_RESULT_ERROR;

        // 鑾峰彇鐢ㄦ埛 ID
        HttpSession session = request.getSession();
        Integer userID = (Integer) session.getAttribute("userID");

        try {
            // 鏇存敼瀵嗙爜
            accountService.passwordModify(userID, passwordInfo);

            result = Response.RESPONSE_RESULT_SUCCESS;
        } catch (UserAccountServiceException e) {
            errorMsg = e.getExceptionDesc();
        }
        // 璁剧疆 Response
        responseContent.setResponseResult(result);
        responseContent.setResponseMsg(errorMsg);
        return responseContent.generateResponse();
    }

    /**
     * 鑾峰彇鍥惧舰楠岃瘉鐮� 灏嗚繑鍥炰竴涓寘鍚�4浣嶅瓧绗︼紙瀛楁瘝鎴栨暟瀛楋級鐨勫浘褰㈤獙璇佺爜锛屽苟涓斿皢鍥惧舰楠岃瘉鐮佺殑鍊艰缃埌鐢ㄦ埛鐨� session 涓�
     *
     * @param time     鏃堕棿鎴�
     * @param response 杩斿洖鐨� HttpServletResponse 鍝嶅簲
     */
    @RequestMapping(value = "checkCode/{time}", method = RequestMethod.GET)
    public void getCheckCode(@PathVariable("time") String time, HttpServletResponse response, HttpServletRequest request) {

        BufferedImage checkCodeImage = null;
        String checkCodeString = null;

        // 鑾峰彇鍥惧舰楠岃瘉鐮侊紝渚濊禆浜巙til/CheckCodeGenerator
        Map<String, Object> checkCode = checkCodeGenerator.generlateCheckCode();

        if (checkCode != null) {
            checkCodeString = (String) checkCode.get("checkCodeString");
            checkCodeImage = (BufferedImage) checkCode.get("checkCodeImage");
        }

        if (checkCodeString != null && checkCodeImage != null) {
            //鑾峰彇response.getOutputStream()
            try (ServletOutputStream outputStream = response.getOutputStream()) {
                // 璁剧疆 Session
                HttpSession session = request.getSession();
                session.setAttribute("checkCode", checkCodeString);

                // 灏嗛獙璇佺爜杈撳嚭
                ImageIO.write(checkCodeImage, "png", outputStream);

                response.setHeader("Pragma", "no-cache");
                response.setHeader("Cache-Control", "no-cache");
                response.setDateHeader("Expires", 0);
                response.setContentType("image/png");
            } catch (IOException e) {
                log.error("fail to get the ServletOutputStream");
            }
        }
    }
}
