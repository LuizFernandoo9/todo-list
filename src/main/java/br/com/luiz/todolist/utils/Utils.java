package br.com.luiz.todolist.utils;

import java.beans.PropertyDescriptor;

import java.util.HashSet;
import java.util.Set;

import org.hibernate.mapping.Array;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.BeanWrapper;
import org.springframework.beans.BeanWrapperImpl;


public class Utils {



    public static void copyNonNullProperties(Object source, Object target){
        BeanUtils.copyProperties(source, target, getNullPropertyNames(source));
    }

    public static String[] getNullPropertyNames(Object source){
        final BeanWrapper src = new BeanWrapperImpl(source);
        PropertyDescriptor [] pds = src.getPropertyDescriptors();

        Set<String> emptyNames = new HashSet<>();

        for(PropertyDescriptor pd : pds){
            Object srcValue = src.getPropertyValue(pd.getName());
            if(srcValue == null){
                emptyNames.add(pd.getName());
            }
        }

        String[] results = new String[emptyNames.size()];

        return emptyNames.toArray(results);
    }
}
