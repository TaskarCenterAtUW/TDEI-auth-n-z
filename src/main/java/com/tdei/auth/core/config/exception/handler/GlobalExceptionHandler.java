package com.tdei.auth.core.config.exception.handler;

import com.tdei.auth.core.config.exception.handler.exceptions.*;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import javax.validation.ConstraintViolationException;
import java.security.InvalidKeyException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@ControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    // handleHttpMediaTypeNotSupported : triggers when the JSON is invalid
    @Override
    protected ResponseEntity<Object> handleHttpMediaTypeNotSupported(HttpMediaTypeNotSupportedException ex, HttpHeaders headers, HttpStatus status, WebRequest request) {

        List<String> details = new ArrayList<>();

        StringBuilder builder = new StringBuilder();
        builder.append(ex.getContentType());
        builder.append(" media type is not supported. Supported media types are ");
        ex.getSupportedMediaTypes().forEach(t -> builder.append(t).append(", "));

        details.add(builder.toString());

        ApiError err = new ApiError(LocalDateTime.now(), HttpStatus.BAD_REQUEST, "Invalid JSON", details);

        return ResponseEntityBuilder.build(err);

    }

    // handleHttpMessageNotReadable : triggers when the JSON is malformed
    @Override
    protected ResponseEntity<Object> handleHttpMessageNotReadable(HttpMessageNotReadableException ex, HttpHeaders headers, HttpStatus status, WebRequest request) {

        List<String> details = new ArrayList<>();
        details.add(ex.getMessage());

        ApiError err = new ApiError(LocalDateTime.now(), HttpStatus.BAD_REQUEST, "Malformed JSON request", details);

        return ResponseEntityBuilder.build(err);
    }

    // handleMethodArgumentNotValid : triggers when @Valid fails
    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex, HttpHeaders headers, HttpStatus status, WebRequest request) {

        List<String> details = new ArrayList<>();
        details = ex.getBindingResult().getFieldErrors().stream().map(error -> error.getField() + " : " + error.getDefaultMessage()).collect(Collectors.toList());

        ApiError err = new ApiError(LocalDateTime.now(), HttpStatus.BAD_REQUEST, "Validation Errors", details);

        return ResponseEntityBuilder.build(err);
    }

    // handleMissingServletRequestParameter : triggers when there are missing parameters
    @Override
    protected ResponseEntity<Object> handleMissingServletRequestParameter(MissingServletRequestParameterException ex, HttpHeaders headers, HttpStatus status, WebRequest request) {

        List<String> details = new ArrayList<>();
        details.add(ex.getParameterName() + " parameter is missing");

        ApiError err = new ApiError(LocalDateTime.now(), HttpStatus.BAD_REQUEST, "Missing Parameters", details);

        return ResponseEntityBuilder.build(err);
    }

    // handleMethodArgumentTypeMismatch : triggers when a parameter's type does not match
    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    protected ResponseEntity<Object> handleMethodArgumentTypeMismatch(MethodArgumentTypeMismatchException ex, WebRequest request) {
        List<String> details = new ArrayList<>();
        details.add(ex.getMessage());

        ApiError err = new ApiError(LocalDateTime.now(), HttpStatus.BAD_REQUEST, "Mismatch Type", details);

        return ResponseEntityBuilder.build(err);
    }

    // handleConstraintViolationException : triggers when @Validated fails
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<?> handleConstraintViolationException(Exception ex, WebRequest request) {

        List<String> details = new ArrayList<>();
        details.add(ex.getMessage());

        ApiError err = new ApiError(LocalDateTime.now(), HttpStatus.BAD_REQUEST, "Constraint Violation", details);

        return ResponseEntityBuilder.build(err);
    }

    // handleResourceNotFoundException : triggers when there is not resource with the specified ID in BDD
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<Object> handleResourceNotFoundException(ResourceNotFoundException ex) {

        List<String> details = new ArrayList<>();
        details.add(ex.getMessage());

        ApiError err = new ApiError(LocalDateTime.now(), HttpStatus.NOT_FOUND, "Resource Not Found", details);

        return ResponseEntityBuilder.build(err);
    }

    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<Object> handleAuthenticationException(InvalidCredentialsException ex) {

        List<String> details = new ArrayList<>();
        details.add(ex.getMessage());

        ApiError err = new ApiError(LocalDateTime.now(), HttpStatus.UNAUTHORIZED, "Unauthorized request", details);

        return ResponseEntityBuilder.build(err);
    }

    @ExceptionHandler(InvalidKeyException.class)
    public ResponseEntity<Object> handleInvalidKeyException(InvalidKeyException ex) {

        List<String> details = new ArrayList<>();
        details.add(ex.getMessage());

        ApiError err = new ApiError(LocalDateTime.now(), HttpStatus.NOT_FOUND, "Unauthorized request", details);

        return ResponseEntityBuilder.build(err);
    }

    @ExceptionHandler(InvalidAccessTokenException.class)
    public ResponseEntity<Object> handleInvalidAccessTokenException(InvalidAccessTokenException ex) {

        List<String> details = new ArrayList<>();
        details.add(ex.getMessage());

        ApiError err = new ApiError(LocalDateTime.now(), HttpStatus.UNAUTHORIZED, "Invalid Access Token", details);

        return ResponseEntityBuilder.build(err);
    }

    // handleNoHandlerFoundException : triggers when the handler method is invalid
    @Override
    protected ResponseEntity<Object> handleNoHandlerFoundException(NoHandlerFoundException ex, HttpHeaders headers, HttpStatus status, WebRequest request) {

        List<String> details = new ArrayList<>();
        details.add(String.format("Could not find the %s method for URL %s", ex.getHttpMethod(), ex.getRequestURL()));

        ApiError err = new ApiError(LocalDateTime.now(), HttpStatus.BAD_REQUEST, "Method Not Found", details);

        return ResponseEntityBuilder.build(err);

    }

    @ExceptionHandler(UserExistsException.class)
    protected ResponseEntity<Object> handleUserExistsException(UserExistsException ex, WebRequest request) {

        List<String> details = new ArrayList<>();
        details.add(ex.getMessage());

        ApiError err = new ApiError(LocalDateTime.now(), HttpStatus.CONFLICT, "User already exists", details);

        return ResponseEntityBuilder.build(err);

    }

    @ExceptionHandler(EmailNotVerifiedException.class)
    protected ResponseEntity<Object> emailNotVerifiedException(EmailNotVerifiedException ex, WebRequest request) {

        List<String> details = new ArrayList<>();
        details.add(ex.getMessage());

        ApiError err = new ApiError(LocalDateTime.now(), HttpStatus.FORBIDDEN, "", details);

        return ResponseEntityBuilder.build(err);

    }

    @ExceptionHandler({Exception.class})
    public ResponseEntity<Object> handleAll(Exception ex, WebRequest request) {

        List<String> details = new ArrayList<>();
        details.add(ex.getLocalizedMessage());

        ApiError err = new ApiError(LocalDateTime.now(), HttpStatus.INTERNAL_SERVER_ERROR, "Error occurred", details);

        return ResponseEntityBuilder.build(err);

    }

}