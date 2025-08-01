package com.study.spring.domain.meal.controller;

import com.study.spring.domain.meal.dto.MealDto;
import com.study.spring.domain.meal.entity.Meal;
import com.study.spring.domain.meal.entity.MealType;
import com.study.spring.domain.meal.service.MealService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;

import java.time.LocalDate;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.net.URL;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Base64;

@RestController
@RequestMapping("/api/meals")
@RequiredArgsConstructor
public class MealController {
    private final MealService mealService;
    private final RestTemplate restTemplate;

    // 파이썬 서버의 텍스트 분석 엔드포인트 호출
    @PostMapping("/analyze-food-text")
    public ResponseEntity<?> analyzeFoodText(@RequestBody Map<String, String> request) {
        try {
            String foodName = request.get("food_name");
            if (foodName == null || foodName.trim().isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("error", "음식 이름을 입력해주세요"));
            }

            // 파이썬 서버 URL (실제 서버 주소로 변경 필요)
            String pythonServerUrl = "http://localhost:8000/api/food/analyze/text";
            
            // 요청 데이터 준비
            Map<String, String> requestBody = Map.of("food_name", foodName);
            
            // HTTP 헤더 설정
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            
            // HTTP 엔티티 생성
            HttpEntity<Map<String, String>> entity = new HttpEntity<>(requestBody, headers);
            
            // 파이썬 서버에 요청
            ResponseEntity<Map> response = restTemplate.exchange(
                pythonServerUrl,
                HttpMethod.POST,
                entity,
                Map.class
            );
            
            return ResponseEntity.ok(response.getBody());
            
        } catch (Exception e) {
            System.err.println("음식 분석 중 오류 발생: " + e.getMessage());
            return ResponseEntity.status(500).body(Map.of(
                "error", "음식 분석 중 오류가 발생했습니다",
                "details", e.getMessage()
            ));
        }
    }

    // 이미지 URL을 base64로 변환하는 유틸리티 메서드
    private String convertImageUrlToBase64(String imageUrl) {
        try {
            URL url = new URL(imageUrl);
            try (InputStream inputStream = url.openStream();
                 ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
                
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    outputStream.write(buffer, 0, bytesRead);
                }
                
                byte[] imageBytes = outputStream.toByteArray();
                return Base64.getEncoder().encodeToString(imageBytes);
            }
        } catch (Exception e) {
            System.err.println("이미지 URL을 base64로 변환 중 오류: " + e.getMessage());
            throw new RuntimeException("이미지를 base64로 변환할 수 없습니다", e);
        }
    }

    // 이미지 분석 엔드포인트
    @PostMapping("/analyze-food-image")
    public ResponseEntity<?> analyzeFoodImage(@RequestBody Map<String, Object> request) {
        try {
            Object imageUrlObj = request.get("image_url");
            String imageUrl = null;
            
            if (imageUrlObj instanceof String) {
                imageUrl = (String) imageUrlObj;
            } else if (imageUrlObj instanceof Map) {
                // 만약 image_url이 객체로 들어온 경우
                Map<String, Object> imageUrlMap = (Map<String, Object>) imageUrlObj;
                imageUrl = (String) imageUrlMap.get("url");
            }
            
            if (imageUrl == null || imageUrl.trim().isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("error", "이미지 URL을 입력해주세요"));
            }

            System.out.println("Received image_url: " + imageUrl);

            // 이미지 URL을 base64로 변환
            String base64Image = convertImageUrlToBase64(imageUrl);
            
            // 파이썬 서버 URL
            String pythonServerUrl = "http://localhost:8000/api/food/analyze";
            
            // 요청 데이터 준비 (base64 이미지 포함)
            Map<String, String> requestBody = Map.of("image_url", base64Image);
            
            // HTTP 헤더 설정
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            
            // HTTP 엔티티 생성
            HttpEntity<Map<String, String>> entity = new HttpEntity<>(requestBody, headers);
            
            // 파이썬 서버에 요청
            ResponseEntity<Map> response = restTemplate.exchange(
                pythonServerUrl,
                HttpMethod.POST,
                entity,
                Map.class
            );
            
            return ResponseEntity.ok(response.getBody());
            
        } catch (Exception e) {
            System.err.println("이미지 분석 중 오류 발생: " + e.getMessage());
            return ResponseEntity.status(500).body(Map.of(
                "error", "이미지 분석 중 오류가 발생했습니다",
                "details", e.getMessage()
            ));
        }
    }

    // 식사 기록 생성
    @PostMapping
    public ResponseEntity<MealDto.Response> createMeal(
            @RequestParam("memberId") Long memberId,  // 이름 명시
            @RequestBody MealDto.Request request) {
        System.out.println("=== createMeal 엔드포인트 호출됨 ===");
        System.out.println("memberId: " + memberId);
        System.out.println("request: " + request);
        return ResponseEntity.ok(mealService.createMeal(memberId, request));
    }

    // 새로운 데이터 구조로 식사 기록 생성
    @PostMapping("/create-with-foods")
    public ResponseEntity<MealDto.Response> createMealWithFoods(
            @RequestParam("memberId") Long memberId,
            @RequestParam("mealType") MealType mealType,
            @RequestParam(value = "imageUrl", required = false) String imageUrl,
            @RequestParam(value = "memo", required = false) String memo,
            @RequestParam(value = "recordWeight", required = false) Double recordWeight,
            @RequestBody List<Map<String, Object>> foodsData) {
        
        System.out.println("=== createMealWithFoods 엔드포인트 호출됨 ===");
        System.out.println("memberId: " + memberId);
        System.out.println("mealType: " + mealType);
        System.out.println("imageUrl: " + imageUrl);
        System.out.println("memo: " + memo);
        
        // 디버깅을 위한 로그 추가
        System.out.println("Received foodsData: " + foodsData);
        System.out.println("foodsData size: " + foodsData.size());
        
        // foodsData를 MealDto.Request 형태로 변환
        List<MealDto.FoodRequest> foods = foodsData.stream()
                .map(foodMap -> {
                    // 각 foodMap의 키들을 출력하여 실제 필드명 확인
                    System.out.println("Food map keys: " + foodMap.keySet());
                    System.out.println("Food map values: " + foodMap);
                    
                    // 모든 가능한 필드명을 시도
                    String foodName = null;
                    if (foodMap.containsKey("foodName")) {
                        foodName = (String) foodMap.get("foodName");
                    } else if (foodMap.containsKey("food_name")) {
                        foodName = (String) foodMap.get("food_name");
                    } else if (foodMap.containsKey("name")) {
                        foodName = (String) foodMap.get("name");
                    } else {
                        // 모든 키를 출력하여 실제 필드명 확인
                        System.out.println("Available keys: " + foodMap.keySet());
                        for (String key : foodMap.keySet()) {
                            System.out.println("Key: " + key + ", Value: " + foodMap.get(key));
                        }
                        throw new IllegalArgumentException("foodName field not found in data");
                    }
                    
                    System.out.println("Extracted foodName: " + foodName);
                    
                    if (foodName == null || foodName.trim().isEmpty()) {
                        throw new IllegalArgumentException("foodName cannot be null or empty");
                    }
                    
                                         return MealDto.FoodRequest.builder()
                             .foodName(foodName)
                             .calories(foodMap.get("calories") != null ? 
                                     Integer.valueOf(foodMap.get("calories").toString()) : null)
                             .carbohydrate(foodMap.get("carbohydrate") != null ? 
                                     Float.valueOf(foodMap.get("carbohydrate").toString()) : null)
                             .protein(foodMap.get("protein") != null ? 
                                     Float.valueOf(foodMap.get("protein").toString()) : null)
                             .fat(foodMap.get("fat") != null ? 
                                     Float.valueOf(foodMap.get("fat").toString()) : null)
                             .sodium(foodMap.get("sodium") != null ? 
                                     Float.valueOf(foodMap.get("sodium").toString()) : null)
                             .fiber(foodMap.get("fiber") != null ? 
                                     Float.valueOf(foodMap.get("fiber").toString()) : null)
                             .foodCategory((String) foodMap.get("foodCategory"))
                             .totalAmount(foodMap.get("totalAmount") != null ? 
                                     Integer.valueOf(foodMap.get("totalAmount").toString()) : null)
                             .quantity(foodMap.get("quantity") != null ? 
                                     Integer.valueOf(foodMap.get("quantity").toString()) : null) // 수량 추가
                             .build();
                })
                .collect(Collectors.toList());

        // 총 칼로리 계산
        Integer totalCalories = foods.stream()
                .mapToInt(food -> food.getCalories() != null ? food.getCalories() : 0)
                .sum();
        
        System.out.println("=== 총 칼로리 계산 결과 ===");
        System.out.println("Total Calories: " + totalCalories);
        
        MealDto.Request request = MealDto.Request.builder()
                .mealType(mealType)
                .imageUrl(imageUrl)
                .memo(memo)
                .foods(foods)

                .recordWeight(recordWeight)

                .totalCalories(totalCalories)

                .build();

        return ResponseEntity.ok(mealService.createMeal(memberId, request));
    }

    // 테스트용 엔드포인트
    @PostMapping("/test")
    public ResponseEntity<String> testEndpoint(@RequestBody Object data) {
        System.out.println("=== test 엔드포인트 호출됨 ===");
        System.out.println("Received data: " + data);
        System.out.println("Data type: " + data.getClass().getName());
        return ResponseEntity.ok("Test endpoint called successfully");
    }
    @GetMapping("/{id}")
    public ResponseEntity<MealDto.Response> getMeal(@PathVariable("id") Long id) {
        return ResponseEntity.ok(mealService.getMeal(id));
    }

    // 전체 식사 기록 조회
    @GetMapping
    public ResponseEntity<List<MealDto.Response>> getAllMeals() {
        return ResponseEntity.ok(mealService.getAllMeals());
    }

    // 회원별 식사 기록 조회
    @GetMapping("/member/{memberId}")
    public ResponseEntity<List<MealDto.Response>> getMealsByMemberId(
            @PathVariable("memberId") Long memberId) {  // 이름 명시
        return ResponseEntity.ok(mealService.getMealsByMemberId(memberId));
    }

    // 회원별 + 식사타입별 조회
    @GetMapping("/member/{memberId}/type/{mealType}")
    public ResponseEntity<List<MealDto.Response>> getMealsByMemberIdAndMealType(
            @PathVariable("memberId") Long memberId,
            @PathVariable("mealType") MealType mealType) {
        return ResponseEntity.ok(mealService.getMealsByMemberIdAndMealType(memberId, mealType));
    }

    // updatedAt 날짜로 식사 기록 조회
    @GetMapping("/modified-date")
    public ResponseEntity<List<MealDto.Response>> getMealsByModifiedDate(@RequestParam("date") String dateStr) {
        LocalDate date = LocalDate.parse(dateStr);
        return ResponseEntity.ok(mealService.getMealsByModifiedDate(date));
    }

    // 회원별 + modifiedAt 날짜로 식사 기록 조회
    @GetMapping("/modified-date/member/{memberId}")
    public ResponseEntity<?> getMealsByMemberIdAndModifiedDate(@PathVariable("memberId") Long memberId, @RequestParam("date") String dateStr) {
        LocalDate date = LocalDate.parse(dateStr);
        List<MealDto.Response> result = mealService.getMealsByMemberIdAndModifiedDate(memberId, date);
        if (result.isEmpty()) {
            return ResponseEntity.ok(Collections.singletonMap("message", "nodata"));
        }
        return ResponseEntity.ok(result);
    }

    // modifiedAt(문자열)로 식사 기록 조회
    // @GetMapping("/modified-date")
    // public ResponseEntity<List<MealDto.Response>> getMealsByModifiedAt(@RequestParam("modifiedAt") String modifiedAt) {
    //     // MealService에 getMealsByModifiedAt(String) 메서드가 없다는 오류가 발생하므로, 
    //     // 올바른 메서드명을 사용하거나 MealService에 해당 메서드가 구현되어 있는지 확인해야 합니다.
    //     // 예시로, getMealsByModifiedAt이 아니라 getMealsByModifiedDate(String)일 수 있으니 아래와 같이 수정합니다.
    //     return ResponseEntity.ok(mealService.getMealsByModifiedAt(modifiedAt));
    // }

    // 식사 기록 수정
    @PutMapping("/{id}")
    public ResponseEntity<MealDto.Response> updateMeal(
            @PathVariable("id") Long id,
            @RequestBody MealDto.Request request) {
        return ResponseEntity.ok(mealService.updateMeal(id, request));
    }

    // 식사 이미지만 수정
    // @PatchMapping("/{id}/image")
    // public ResponseEntity<Void> updateMealImage(
    //         @PathVariable("id") Long id,
    //         @RequestBody Map<String, String> body) {
    //     String imageUrl = body.get("imageUrl");
    //     mealService.updateMealImage(id, imageUrl);
    //     return ResponseEntity.noContent().build();
    // }

    // 식사 이미지 업로드
    // @PatchMapping(value = "/{id}/image-upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    // public ResponseEntity<Void> uploadMealImage(
    //         @PathVariable("id") Long id,
    //         @RequestPart("image") org.springframework.web.multipart.MultipartFile imageFile) {
    //     mealService.uploadMealImage(id, imageFile);
    //     return ResponseEntity.noContent().build();
    // }

    // 식사 기록 삭제
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteMeal(@PathVariable("id") Long id) {
        mealService.deleteMeal(id);
        return ResponseEntity.noContent().build();
    }

    // 식사 이미지 저장
    // @PostMapping("/{id}/")
    // public void testCreate(@ModelAttribute MealDto.Request request) {
    //     mealService.uploadMealImage(request);
    // }
} 