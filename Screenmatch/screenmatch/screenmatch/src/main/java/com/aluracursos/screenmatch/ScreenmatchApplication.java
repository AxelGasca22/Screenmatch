package com.aluracursos.screenmatch;

import com.aluracursos.screenmatch.principal.Principal;
import com.aluracursos.screenmatch.repositorio.SerieRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

///books?search=moby-dick

@SpringBootApplication
public class ScreenmatchApplication {

	public static void main(String[] args) {
		SpringApplication.run(ScreenmatchApplication.class, args);
	}
}