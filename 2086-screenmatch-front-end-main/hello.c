#include <stdio.h>

#define NUM_TRAMAS 33
#define TAMANO_TRAMA 64

// Arreglos de comandos y respuestas
char ss[][5] = {"RR", "RNR", "REJ", "SREJ"}; // Comandos supervisores
char uc[][5] = {"UI", "SIM", "-", "SARM", "UP", "-", "-", "SABM"}; // Comandos no numerados
char ur[][5] = {"UI", "RIM", "-", "DM", "-", "-", "-", "RD"}; // Respuestas no numeradas

void analizar_cabecera_llc(unsigned char trama[]);
void analizaARP(unsigned char trama[]);

unsigned short calcular_checksum(unsigned char *data, int length) {
    unsigned long sum = 0;
	int i=0;
    for (i = 0; i < length; i += 2) {
        unsigned short word = (data[i] << 8) + data[i + 1];
        sum += word;
        
        // Si hay desbordamiento, sumamos el carry
        if (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + 1;
        }
    }
    
    // Complementamos el resultado
    return ~sum & 0xFFFF;
}

void verificar_checksum(unsigned char *trama) {
    printf(".:: Verificación de CHECKSUM ::.\n");

    unsigned short checksum_recibido = (trama[24] << 8) | trama[25];
    trama[24] = 0; // Configuramos el checksum a 0 para el cálculo
    trama[25] = 0;

    unsigned short checksum_calculado = calcular_checksum(trama + 14, 20); // Cabecera IP es de 20 bytes

    printf("CHECKSUM calculado: 0x%.4X\n", checksum_calculado);
    printf("CHECKSUM recibido:  0x%.4X\n", checksum_recibido);

    if (checksum_recibido == checksum_calculado) {
        printf("Resultado: ACK (CHECKSUM correcto)\n");
    } else if (checksum_recibido == 0x0000) {
        printf("Resultado: CHECKSUM calculado: 0x%.4X\n", checksum_calculado);
    } else {
        printf("Resultado: NACK (CHECKSUM incorrecto)\n");
    }
}

void analizar_llc(unsigned char trama[]) {
    unsigned short tipo = (trama[12] << 8) | trama[13];  // Extraemos el tipo de la cabecera LLC

    printf(".:: Cabecera Ethernet ::.\n");
    printf("MAC destino: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", 
            trama[0], trama[1], trama[2], trama[3], trama[4], trama[5]);
    printf("MAC origen: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", 
            trama[6], trama[7], trama[8], trama[9], trama[10], trama[11]);

    if (tipo < 1500) {
        printf("Tamaño (LLC): %d bytes, ToT\n", tipo);
        analizar_cabecera_llc(trama);
    } else if (tipo == 2048) {
        printf("TIPO: IP\n");
        verificar_checksum(trama);
    } else if (tipo == 2054) {
        printf("TIPO: ARP\n");
        analizaARP(trama);
    } else {
        printf("TIPO: Desconocido: 0x%.4x\n", tipo);
    }
}

void analizar_cabecera_llc(unsigned char trama[]) {
    unsigned char control = trama[16];  // Byte de control LLC
    unsigned char tipo_trama = control & 0x03;  // Evaluamos los últimos 2 bits
    unsigned char pf_bit = trama[17] & 0x01;  // Bit P/F en la segunda parte

    printf("\n.:: Cabecera LLC ::.\n");

    switch (tipo_trama) {
        case 0x00:  // Trama I (Information)
        case 0x02:
            printf("Trama I\n");
            printf("N(s)=%d, N(r)=%d ", (control >> 1) & 0x7F, trama[17] >> 1);
            if (pf_bit) {
                printf("- P/F: Activo\n");
            } else {
                printf("P/F: -");
            }
            break;

        case 0x01:  // Trama S (Supervisory)
            printf("Trama S: %s\n", ss[(control >> 2) & 0x03]);
            if (pf_bit) {
                printf("- P/F: Activo\n");
            } else {
                printf("P/F: -");
            }
            break;

        case 0x03:  // Trama U (Unnumbered)
            printf("Trama U\n");
            printf("P/F: %s\n", pf_bit ? "Activo" : "-");
            break;

        default:
            printf("Tipo de trama desconocido\n");
    }
}

void analizaARP(unsigned char trama[]) {
    printf(".:: Cabecera ARP ::.\n");

    unsigned short hardware_type = trama[14] << 8 | trama[15];
    if (hardware_type == 1) {
        printf("Tipo de hardware: Ethernet\n");
    } else if (hardware_type == 6) {
        printf("Tipo de hardware: IEEE 802 LAN\n");
    } else {
        printf("Tipo de hardware: Otro (%d)\n", hardware_type);
    }

    unsigned short protocol_type = trama[16] << 8 | trama[17];
    if (protocol_type == 0x0800) {
        printf("Tipo de protocolo: IPv4\n");
    } else {
        printf("Tipo de protocolo: Otro (%.2x %.2x)\n", trama[16], trama[17]);
    }

    printf("Tamaño de dirección de hardware: %d bytes\n", trama[18]);
    printf("Tamaño de dirección de protocolo: %d bytes\n", trama[19]);

    unsigned short operation = trama[20] << 8 | trama[21];
    if (operation == 1) {
        printf("Operación: Solicitud (ARP Request)\n");
    } else if (operation == 2) {
        printf("Operación: Respuesta (ARP Reply)\n");
    } else {
        printf("Operación: Otro (%d)\n", operation);
    }

    printf("Dirección de protocolo (IP) origen: %d.%d.%d.%d\n",
           trama[28], trama[29], trama[30], trama[31]);

    printf("Dirección de protocolo (IP) destino: %d.%d.%d.%d\n",
           trama[38], trama[39], trama[40], trama[41]);

    printf("\n");
}

int main() {
    unsigned char tramaARP[][128]={{
	0x00, 0x23, 0x8b, 0x46, 0xe9, 0xad, 0x00, 0x1f, 0x45, 0x9d, 0x1e, 0xa2, 0x08, 0x00, 0x45, 0x00, //TIP
	0x00, 0x6f, 0x90, 0x30, 0x40, 0x00, 0xfb, 0x11, 0x24, 0xe7, 0x94, 0xcc, 0x67, 0x02, 0x94, 0xcc, 
	0x39, 0xcb, 0x00, 0x35, 0x04, 0x0c, 0x00, 0x5b, 0xe8, 0x60, 0xe2, 0x1a, 0x85, 0x80, 0x00, 0x01, 
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77, 0x03, 0x69, 0x73, 0x63, 0x05, 0x65, 
	0x73, 0x63, 0x6f, 0x6d, 0x03, 0x69, 0x70, 0x6e, 0x02, 0x6d, 0x78, 0x00, 0x00, 0x1c, 0x00, 0x01, 
	0xc0, 0x14, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x21, 0x04, 0x64, 0x6e, 0x73, 
	0x31, 0xc0, 0x1a, 0x03, 0x74, 0x69, 0x63, 0xc0, 0x1a, 0x77, 0xec, 0xdf, 0x29, 0x00, 0x00, 0x2a, 
	0x30, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x12, 0x75, 0x00, 0x00, 0x00, 0x2a, 0x30},
	{
	0x00, 0x1f, 0x45, 0x9d, 0x1e, 0xa2, 0x00, 0x23, 0x8b, 0x46, 0xe9, 0xad, 0x08, 0x00, 0x45, 0x00, //TIP
	0x00, 0x3c, 0x04, 0x57, 0x00, 0x00, 0x80, 0x00, 0x98, 0x25, 0x94, 0xcc, 0x39, 0xcb, 0x94, 0xcc, 
	0x3a, 0xe1, 0x08, 0x00, 0x49, 0x5c, 0x03, 0x00, 0x01, 0x00, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 
	0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 
	0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69},
	{
	0x02, 0xff, 0x53, 0xc3, 0xe9, 0xab, 0x00, 0xff, 0x66, 0x7f, 0xd4, 0x3c, 0x08, 0x00, 0x45, 0x00, //T11
	0x00, 0x30, 0x2c, 0x00, 0x40, 0x00, 0x80, 0x06, 0x4b, 0x74, 0xc0, 0xa8, 0x01, 0x02, 0xc0, 0xa8, 
	0x01, 0x01, 0x04, 0x03, 0x00, 0x15, 0x00, 0x3b, 0xcf, 0x44, 0x00, 0x00, 0x00, 0x00, 0x70, 0x20, 
	0x20, 0x00, 0x0c, 0x34, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x04, 0x02              
	}};
	
	
    //analizar_llc(tramaARP);
    int i=0;
    for (i = 0; i < 3; i++) {
    printf("\nProcesando trama %d:\n", i + 1);
    analizar_llc(tramaARP[i]);
}

    
    return 0;
}
