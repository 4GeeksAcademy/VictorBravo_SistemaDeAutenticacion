import React, { Component } from "react";
import "../../styles/home.css"

export const Footer = () => (
	<>
		<footer className="footer text-center bg-dark text-white py-3">
                <p>
                    Derechos reservados © 2024 TuEmpresa. | <a href="/contact" className="text-light">Contacto</a> | 
                    <a href="/privacy" className="text-light">Política de Privacidad</a>
                </p>
            </footer>
	</>
);
