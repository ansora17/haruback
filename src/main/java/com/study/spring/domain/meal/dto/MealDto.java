package com.study.spring.domain.meal.dto;

import com.study.spring.domain.meal.entity.Food;
import com.study.spring.domain.meal.entity.Meal;
import com.study.spring.domain.meal.entity.MealType;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class MealDto {

    @NoArgsConstructor
    @AllArgsConstructor
    @Getter
    @Builder
    public static class Request {
        private MealType mealType;
        private String imageUrl;
        private String memo;
        private List<FoodRequest> foods;
        private LocalDateTime modifiedAt;
        private Integer totalCalories;
        private Double recordWeight;
    }

    @NoArgsConstructor
    @AllArgsConstructor
    @Getter
    @Builder
    public static class Response {
        private Long id;
        private Long memberId;
        private MealType mealType;
        private String imageUrl;
        private String memo;
        private List<FoodResponse> foods;
        private LocalDate createdAt;
        private LocalDate updatedAt;
        private LocalDateTime modifiedAt;
        private Double recordWeight;
        private Integer totalCalories;

        public static Response from(Meal meal) {
            List<FoodResponse> foods = meal.getFoods() != null ? 
                    meal.getFoods().stream()
                            .map(FoodResponse::from)
                            .collect(Collectors.toList()) : 
                    new ArrayList<>();
            
            // 총 칼로리 계산
            Integer totalCalories = foods.stream()
                    .mapToInt(food -> food.getCalories() != null ? food.getCalories() : 0)
                    .sum();
            
            return Response.builder()
                    .id(meal.getId())
                    .memberId(meal.getMember().getId())
                    .mealType(meal.getMealType())
                    .imageUrl(meal.getImageUrl())
                    .memo(meal.getMemo())
                    .foods(foods)
                    .createdAt(meal.getCreatedAt() != null ? meal.getCreatedAt().toLocalDate() : null)
                    .updatedAt(meal.getUpdatedAt() != null ? meal.getUpdatedAt().toLocalDate() : null)
                    .modifiedAt(meal.getModifiedAt())
                    .recordWeight(meal.getRecordWeight())
                    .totalCalories(totalCalories)
                    .build();
        }
    }

    @NoArgsConstructor
    @AllArgsConstructor
    @Getter
    @Builder
    public static class FoodRequest {
        private String foodName;
        private Integer calories;
        private Float carbohydrate; // 클라이언트 데이터 구조에 맞게 단수형으로 변경
        private Float protein;
        private Float fat;
        private Float sodium;
        private Float fiber;
        private String foodCategory; // 클라이언트 데이터 구조에 맞게 카멜케이스로 변경
        private Integer totalAmount; // 클라이언트 데이터 구조에 맞게 카멜케이스로 변경
        private Integer quantity; // 수량 추가
    }

    @NoArgsConstructor
    @AllArgsConstructor
    @Getter
    @Builder
    public static class FoodResponse {
        private Long id;
        private String foodName;
        private Integer calories;
        private Float carbohydrate;
        private Float protein;
        private Float fat;
        private Float sodium;
        private Float fiber;
        private String foodCategory;
        private Integer totalAmount;
        private Integer quantity; // 수량 추가

        public static FoodResponse from(Food food) {
            return FoodResponse.builder()
                    .id(food.getId())
                    .foodName(food.getFoodName())
                    .calories(food.getCalories())
                    .carbohydrate(food.getCarbohydrate())
                    .protein(food.getProtein())
                    .fat(food.getFat())
                    .sodium(food.getSodium())
                    .fiber(food.getFiber())
                    .foodCategory(food.getFoodCategory())
                    .totalAmount(food.getTotalAmount())
                    .quantity(food.getQuantity()) // 수량 추가
                    .build();
        }
    }
} 