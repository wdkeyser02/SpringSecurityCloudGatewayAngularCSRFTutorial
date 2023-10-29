package willydekeyser.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/resourceserver01")
public class HomeController {

	@GetMapping("/")
	public String getHome() {
		return "Spring Resource Server 01";
	}
	
	@PostMapping("/")
	public String postHome(@RequestBody String id) {
		return "Spring Resource Server 01 " + id;
	}
}