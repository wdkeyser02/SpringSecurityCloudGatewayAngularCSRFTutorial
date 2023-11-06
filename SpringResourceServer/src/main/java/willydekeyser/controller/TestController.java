package willydekeyser.controller;

import java.util.ArrayList;
import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/resourceserver01")
public class TestController {

	private List<String> testList = new ArrayList<>();
	
 	@GetMapping("/test")
	public List<String> getTest() {
		return testList;
	}
	
	@PostMapping("/test")
	public List<String> postTest(@RequestBody String test) {
		testList.add(test);
		return testList;

	}
}