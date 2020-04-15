#ifndef __THREAD_FIXED_POINT_H
#define __THREAD_FIXED_POINT_H


typedef int fixed;

#define fractional_bits 16
/* Convert other type value to fixed-point value. */
#define convert_other_fixed(A) ((fixed)(A << fractional_bits))
/* Convert fixed-point value to other type value. */
#define convert_fixed_other(A) (A >> fractional_bits)
/* Add two fixed-point value. */
#define add_fixed_fixed(A,B) (A + B)
/* Add a fixed-point value and an other type value. */
#define add_fixed_other(A,B) (A + (B << fractional_bits))
/* Substract two fixed-point value. */
#define sub_fixed_fixed(A,B) (A - B)
/* Substract an other type value from a fixed-point value A */
#define sub_fixed_other(A,B) (A - (B << fractional_bits))
/* Multiply a fixed-point value and an other type value. */
#define mul_fixed_other(A,B) (A * B)
/* Multiply two fixed-point value. */
#define mul_fixed_fixed(A,B) ((fixed)(((int64_t) A) * B >> fractional_bits))
/* Divide a fixed-point value A by an other type value. */
#define div_fixed_other(A,B) (A / B)
/* Divide a fixed-point value A by a fixed-point value. */
#define div_fixed_fixed(A,B) ((fixed)((((int64_t) A) << fractional_bits) / B))
/* Round a fixed-point to the nearest integer */
#define round_nearest(A) (A >= 0 ? ((A + (1 << (fractional_bits - 1))) >> fractional_bits ) : ((A - (1 << (fractional_bits - 1))) >> fractional_bits))


typedef int fixed_t;
/* 16 LSB used for fractional part. */
#define FP_SHIFT_AMOUNT 16
/* Convert a value to fixed-point value. */
#define FP_CONST(A) ((fixed_t)(A << FP_SHIFT_AMOUNT))
/* Add two fixed-point value. */
#define FP_ADD(A,B) (A + B)
/* Add a fixed-point value A and an int value B. */
#define FP_ADD_MIX(A,B) (A + (B << FP_SHIFT_AMOUNT))
/* Substract two fixed-point value. */
#define FP_SUB(A,B) (A - B)
/* Substract an int value B from a fixed-point value A */
#define FP_SUB_MIX(A,B) (A - (B << FP_SHIFT_AMOUNT))
/* Multiply a fixed-point value A by an int value B. */
#define FP_MULT_MIX(A,B) (A * B)
/* Divide a fixed-point value A by an int value B. */
#define FP_DIV_MIX(A,B) (A / B)
/* Multiply two fixed-point value. */
#define FP_MULT(A,B) ((fixed_t)(((int64_t) A) * B >> FP_SHIFT_AMOUNT))
/* Divide two fixed-point value. */
#define FP_DIV(A,B) ((fixed_t)((((int64_t) A) << FP_SHIFT_AMOUNT) / B))
/* Get integer part of a fixed-point value. */
#define FP_INT_PART(A) (A >> FP_SHIFT_AMOUNT)
/* Get rounded integer of a fixed-point value. */
#define FP_ROUND(A) (A >= 0 ? ((A + (1 << (FP_SHIFT_AMOUNT - 1))) >> FP_SHIFT_AMOUNT) \
        : ((A - (1 << (FP_SHIFT_AMOUNT - 1))) >> FP_SHIFT_AMOUNT))

        
#endif /* threads/fixed_point.h */
