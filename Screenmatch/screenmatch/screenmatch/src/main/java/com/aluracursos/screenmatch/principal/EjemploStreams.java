package com.aluracursos.screenmatch.principal;

import java.util.Arrays;
import java.util.List;

public class EjemploStreams {
    public void muestraEjemplo(){
        List<String> nombres = Arrays.asList("Fernanda", "Maria", "Erick", "Genesys");

        nombres.stream()
                .sorted()
                .limit(2)
                .filter(n -> n.startsWith("E"))
                .map(n -> n.toUpperCase())
                .forEach(System.out::println);
    }
}
