import React, { useContext, useState } from "react";
import "../../styles/home.css";
import { useNavigate } from "react-router-dom";
import Login from "../component/login";

export const Home = () => {
	const [isLoginModalOpen, setIsLoginModalOpen] = useState(false);
	const navigate = useNavigate();

	const handleRegisterRedirect = () => {
		navigate("/signup");
	};

	return (
		<div className="container-fluid p-0">
			<section className="hero text-center bg-primary text-white py-5">
				<h1 className="display-4">Bienvenido al Sistema de Autenticación</h1>
				<p className="lead">Un sistema seguro y fácil de usar para gestionar tu autenticación.</p>
				<button className="btn btn-light btn-lg me-3" onClick={() => setIsLoginModalOpen(true)}>
					Iniciar Sesión
				</button>
				<button className="btn btn-outline-light btn-lg" onClick={handleRegisterRedirect}>
					Registrarse
				</button>
			</section>

			<section className="features text-center py-5">
				<h2 className="mb-4">Características del Sistema</h2>
				<div className="row">
					<div className="col-md-4">
						<i className="fas fa-lock fa-3x"></i>
						<h4>Seguridad</h4>
						<p>Implementación de medidas de seguridad avanzadas para proteger tus datos.</p>
					</div>
					<div className="col-md-4">
						<i className="fas fa-user fa-3x"></i>
						<h4>Facilidad de Uso</h4>
						<p>Interfaz intuitiva que hace que la gestión de cuentas sea simple y rápida.</p>
					</div>
					<div className="col-md-4">
						<i className="fas fa-headset fa-3x"></i>
						<h4>Soporte Técnico</h4>
						<p>Asistencia 24/7 para resolver cualquier inconveniente que puedas tener.</p>
					</div>
				</div>
			</section>

			{/* Modal de Login */}
			{isLoginModalOpen && (
				<div className="modal fade show" style={{ display: "block" }} tabIndex="-1" role="dialog" aria-hidden="true">
					<div className="modal-dialog" role="document">
						<div className="modal-content">
							<div className="modal-header">
								<h5 className="modal-title">Iniciar Sesión</h5>
								<button type="button" className="btn-close" onClick={() => setIsLoginModalOpen(false)} aria-label="Cerrar" />
							</div>
							<div className="modal-body">
								<Login onClose={() => setIsLoginModalOpen(false)} />
							</div>
						</div>
					</div>
				</div>
			)}
		</div>
	);
};