/**
 * NOTE: This class is auto generated by the swagger code generator program (3.0.35).
 * https://github.com/swagger-api/swagger-codegen
 * Do not edit the class manually.
 */
package com.tdei.auth.controller.authentication.contract;

import com.tdei.auth.core.config.exception.handler.exceptions.InvalidAccessTokenException;
import com.tdei.auth.model.auth.dto.RegisterUser;
import com.tdei.auth.model.auth.dto.TokenResponse;
import com.tdei.auth.model.auth.dto.UserProfile;
import com.tdei.auth.model.common.dto.LoginModel;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import javax.validation.Valid;
import javax.validation.constraints.Size;
import java.security.InvalidKeyException;
import java.util.Optional;

@Validated
public interface IAuthentication {

    @Operation(summary = "Get user profile by username", description = "Get user profile by username.  Returns the user profile. ",
            tags = {"Authentication"})
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful response -  Returns the user profile.", content = @Content(mediaType = "application/json", schema = @Schema(implementation = UserProfile.class))),

            @ApiResponse(responseCode = "404", description = "API Key is invalid.", content = @Content),

            @ApiResponse(responseCode = "500", description = "An server error occurred.", content = @Content)})
    @RequestMapping(value = "getUserByUsername",
            produces = {"application/json"},
            consumes = {"*"},
            method = RequestMethod.GET)
    ResponseEntity<UserProfile> getUserByUserName(String userName) throws Exception;

    @Operation(summary = "User Registration API", description = "User Registration API.  Returns the user profile for the newly created user. ",
            tags = {"Authentication"})
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful response -  Returns the user profile for the newly created user.", content = @Content(mediaType = "application/json", schema = @Schema(implementation = UserProfile.class))),

            @ApiResponse(responseCode = "404", description = "API Key is invalid.", content = @Content),

            @ApiResponse(responseCode = "500", description = "An server error occurred.", content = @Content)})
    @RequestMapping(value = "registerUser",
            produces = {"application/json"},
            consumes = {"application/json"},
            method = RequestMethod.POST)
    ResponseEntity<UserProfile> registerUser(@Valid @RequestBody RegisterUser user) throws Exception;

    @Operation(summary = "Validates the API Key", description = "Validates the API Key.  Returns the user profile for the validated api key. ",
            tags = {"Authentication"})
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful response - Returns the user profile for the validated api key.", content = @Content(mediaType = "application/json", schema = @Schema(implementation = UserProfile.class))),

            @ApiResponse(responseCode = "404", description = "API Key is invalid.", content = @Content),

            @ApiResponse(responseCode = "500", description = "An server error occurred.", content = @Content)})
    @RequestMapping(value = "validateApiKey",
            produces = {"application/json"},
            consumes = {"text/plain"},
            method = RequestMethod.POST)
    ResponseEntity<UserProfile> validateApiKey(@RequestBody String apiKey) throws InvalidKeyException;

    @Operation(summary = "Validates the API Key", description = "Validates the Access Token.  Returns the user profile for the validated access token. ",
            tags = {"Authentication"})
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful response - Returns the user profile for the validated access token.", content = @Content(mediaType = "application/json", schema = @Schema(implementation = UserProfile.class))),

            @ApiResponse(responseCode = "404", description = "Access token is invalid.", content = @Content),

            @ApiResponse(responseCode = "500", description = "An server error occurred.", content = @Content)})
    @RequestMapping(value = "validateAccessToken",
            produces = {"application/json"},
            consumes = {"text/plain"},
            method = RequestMethod.POST)
    ResponseEntity<UserProfile> validateAccessToken(@RequestBody String token) throws InvalidAccessTokenException;

    @Operation(summary = "List available API versions", description = "Returns a json list of the versions of the TDEI API which are available.",
            tags = {"Authentication"})
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful response - Returns the access token for the validated user.", content = @Content(mediaType = "application/json", schema = @Schema(implementation = TokenResponse.class))),

            @ApiResponse(responseCode = "401", description = "This request is unauthorized.", content = @Content),

            @ApiResponse(responseCode = "500", description = "An server error occurred.", content = @Content)})
    @RequestMapping(value = "authenticate",
            produces = {"application/json"},
            method = RequestMethod.POST)
    ResponseEntity<TokenResponse> authenticate(@Valid @RequestBody LoginModel loginModel);


    @Operation(summary = "Check user access", description = "Returns boolean flag if user satisfies the roles.",
            tags = {"Authentication"})
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful response - Returns boolean flag if user satisfies the roles.", content = @Content(mediaType = "application/json", schema = @Schema(implementation = Boolean.class))),

            @ApiResponse(responseCode = "401", description = "This request is unauthorized.", content = @Content),

            @ApiResponse(responseCode = "500", description = "An server error occurred.", content = @Content)})
    @RequestMapping(value = "hasPermission",
            produces = {"application/json"},
            method = RequestMethod.GET)
    ResponseEntity<Boolean> hasPermission(@Parameter(in = ParameterIn.QUERY, description = "User identifier") @RequestParam() String userId, @Parameter(in = ParameterIn.QUERY, description = "Agency Id") @RequestParam(required = false) Optional<String> agencyId, @Parameter(in = ParameterIn.QUERY, description = "Roles") @Size(min = 1) @RequestParam() String[] roles, @Parameter(in = ParameterIn.QUERY, description = "Affirmative, true to satisfy atleast one role otherwise all roles") @RequestParam(required = false, defaultValue = "false") Optional<Boolean> affirmative);


    @Operation(summary = "Re-issue access token", description = "Re-issues access token provided refresh token",
            tags = {"Authentication"})
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful validation of refresh token - Returns the refreshed access token.", content = @Content(mediaType = "application/json", schema = @Schema(implementation = TokenResponse.class))),

            @ApiResponse(responseCode = "404", description = "Access token is invalid.", content = @Content),

            @ApiResponse(responseCode = "500", description = "An server error occurred.", content = @Content)})
    @RequestMapping(value = "refreshToken",
            produces = {"application/json"},
            consumes = {"application/json"},
            method = RequestMethod.POST)
    ResponseEntity<TokenResponse> reIssueToken(@RequestBody String refreshToken);

    @Operation(summary = "Generate secret token", description = "Returns time bound secret token.",
            tags = {"Authentication"})
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful response - Returns time bound secret token.", content = @Content(mediaType = "text/plain", schema = @Schema(implementation = String.class))),
            @ApiResponse(responseCode = "500", description = "An server error occurred.", content = @Content)})
    @RequestMapping(value = "generateSecret",
            produces = {"text/plain"},
            method = RequestMethod.GET)
    ResponseEntity<String> generateSecret();

    @Operation(summary = "Validates secret token", description = "Returns boolean flag if secret token is valid.",
            tags = {"Authentication"})
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful response - Returns boolean flag if secret token is valid.", content = @Content(mediaType = "text/plain", schema = @Schema(implementation = String.class))),
            @ApiResponse(responseCode = "500", description = "An server error occurred.", content = @Content)})
    @RequestMapping(value = "validateSecret",
            produces = {"text/plain"},
            consumes = {"application/json"},
            method = RequestMethod.PUT)
    ResponseEntity<String> validateSecret(@RequestBody String secret);
}

