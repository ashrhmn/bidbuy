package controllers;

import dtos.UserDto;
import model.User;
import org.springframework.beans.propertyeditors.StringTrimmerEditor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;
import services.UserService;
import utils.NumberUtils;

import java.util.List;

@RestController
@RequestMapping("/user")
@CrossOrigin(origins = "*")
public class UserController {
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    public UserController(UserService userService, PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
    }


    @InitBinder
    public void initBinder(WebDataBinder webDataBinder) {
        StringTrimmerEditor stringTrimmerEditor = new StringTrimmerEditor(true);
        webDataBinder.registerCustomEditor(String.class, stringTrimmerEditor);
    }

    @RequestMapping("/")
    public List<UserDto> getAll(
            @RequestParam(name = "page", required = false) String page,
            @RequestParam(name = "view", required = false) String viewPerPage
    ) {
        int pageNo = NumberUtils.stringToNumOrNeg(page);
        int view = NumberUtils.stringToNumOrNeg(viewPerPage);
        return this.userService
                .getAll(
                        Math.max(pageNo, 1),
                        Math.max(view, 10)
                );
    }

    @RequestMapping("/count")
    public Integer getAllCount() {
        return this.userService.getAllCount();
    }

    @RequestMapping("/{id}")
    public UserDto getById(@PathVariable(name = "id", required = true) int id) {
        return this.userService.getById(id);
    }

    @RequestMapping("/getByName")
    public User getByName(@RequestParam(name = "name", required = true) String name) {
        return this.userService.getByUsername(name);
    }

    @RequestMapping("/delete")
    public void delete(@RequestParam(name = "id", required = true) int id) {
        this.userService.delete(id);
    }

    @RequestMapping("/update")
    public void update(User user) {
        this.userService.update(user);
    }

    @PostMapping("/save")
    public void save(@RequestBody User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        this.userService.save(user);
    }


}
