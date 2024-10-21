import React, { useContext, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import Login from "./login";
import { Context } from "../store/appContext";

const Navbar = () => {
    const { actions } = useContext(Context);
    const navigate = useNavigate();
    const [isLoginModalOpen, setIsLoginModalOpen] = useState(false);
    const [logoutMessage, setLogoutMessage] = useState("");

    const handleModalClose = () => {
        setIsLoginModalOpen(false); // Cierra el modal
    };

    const handleLogout = async () => {
        alert("Adiós!"); // Mostrar el mensaje de despedidao
        setTimeout(() => {

            // Cerrar sesión y redirigir    
            actions.logout(); // isLogged pasa a falso
            navigate("/"); // Redirige a la página de inicio
        }, 1000); // Retraso de 1 segundo


        try {
            const response = await fetch(`${process.env.BACKEND_URL}/api/logout`, {
                method: "POST",
                credentials: "include" // Enviar cookies
            });

            if (response.ok) {
                console.log("Logout exitoso");
                // Actualiza el estado tras el logout
                actions.logout();
                navigate("/"); // Redirigir tras logout
            }
        } catch (error) {
            console.error("Error cerrando sesión", error);
        }
    };

    const handleRegisterRedirect = () => {
        navigate("/signup"); // Redirige a la página de registro
    };

    return (
        <>
            <div className="container-fluid p-0">
                <header className="header d-flex justify-content-between align-items-center p-3 bg-dark text-white">
                    <div className="logo d-flex align-items-center">
                        <span>SecurApp</span>
                    </div>
                    <nav className="nav">
                        <Link to="/" className="nav-link">Inicio</Link>
                        <Link to="/dashboard" className="nav-link">Dashboard</Link>
                        {!actions.isAuthenticated() ? ( // Asegúrate de que la condición sea correcta
                            <button className="btn btn-outline-light me-2" onClick={handleRegisterRedirect}>
                                Registrarse
                            </button>
                        ) : null}
                        {actions.isAuthenticated() ? (
                            <button className="btn btn-light" onClick={handleLogout}>
                                Cerrar Sesión
                            </button>
                        ) : (
                            <button className="btn btn-light" onClick={() => setIsLoginModalOpen(true)}>
                                Iniciar Sesión
                            </button>
                        )}
                    </nav>
                </header>
            </div>

            {/* Modal de Login */}
            {isLoginModalOpen && (
                <div
                    className="modal fade show"
                    style={{ display: "block" }}
                    tabIndex="-1"
                    role="dialog"
                    aria-labelledby="loginModalLabel"
                    aria-hidden="true"
                >
                    <div className="modal-dialog" role="document">
                        <div className="modal-content">
                            <div className="modal-header">
                                <h5 className="modal-title" id="loginModalLabel">Iniciar Sesión</h5>
                                <button
                                    type="button"
                                    className="btn-close"
                                    onClick={handleModalClose}
                                    aria-label="Cerrar"
                                />
                            </div>
                            <div className="modal-body">
                                <Login onClose={handleModalClose} />
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </>
    );
};

export default Navbar;

