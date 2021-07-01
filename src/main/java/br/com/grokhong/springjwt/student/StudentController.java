package br.com.grokhong.springjwt.student;

import java.util.Arrays;
import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1/students")
public class StudentController {

    private final List<Student> list = Arrays.asList(new Student(1, "Paulo"), new Student(2, "Pedro"),
            new Student(3, "Jefferson"));

    @GetMapping(path = "/{studentId}")
    public Student getStudent(@PathVariable("studentId") Integer studentId) {
        return list.stream().filter(student -> studentId.equals(student.getStudentId())).findFirst()
                .orElseThrow(() -> new IllegalStateException("Student: " + studentId + " does not exists."));
    }
}
