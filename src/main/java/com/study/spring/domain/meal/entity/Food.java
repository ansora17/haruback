package com.study.spring.domain.meal.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@AllArgsConstructor
@Builder
@Entity
@Table(name = "foods")
@Getter
@NoArgsConstructor
public class Food {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "meals_id", nullable = false)
    @Setter
    private Meal meal;

    @Column(nullable = false)
    private String foodName;

    private Integer calories;
    private Float carbohydrate;
    private Float protein;
    private Float fat;
    private Float sodium;
    private Float fiber;
    private Integer totalAmount; // 총 양 (g)
    private Integer quantity; // 수량
    
    @Column(length = 20)
    private String foodCategory; // 예: 한식, 양식, 중식, 일식, 분식 등
} 