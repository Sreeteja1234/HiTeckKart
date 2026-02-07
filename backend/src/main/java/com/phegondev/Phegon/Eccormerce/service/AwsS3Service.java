package com.phegondev.Phegon.Eccormerce.service;

import org.springframework.web.multipart.MultipartFile;

public interface AwsS3Service {
    String saveImageToS3(MultipartFile image);
}
