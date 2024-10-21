import React, { useState, useContext } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import "../../styles/signupform.css";
import Login from "../component/login";
import { Context } from '../store/appContext';

export const Signup = () => {
    const [first_name, setFirstName] = useState('');
    const [last_name, setLastName] = useState('');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [showPassword, setShowPassword] = useState(false)
    const [isLoginModalOpen, setIsLoginModalOpen] = useState(false);
    const [success, setSuccess] = useState('');
    const { store, actions } = useContext(Context)
    const navigate = useNavigate();

    const validatePassword = (password) => {
        const passwordRegex = /^(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*(),.?":{}|<>]).{8,}$/;
        return passwordRegex.test(password);
    };

    const validateEmail = (email) => {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    };

    const handleSignup = async (e) => {
        e.preventDefault();
        setError(''); // Reset error
        setSuccess(''); // Reset mensaje éxito

        // Validar campos requeridos
        if (!first_name || !last_name || !email || !password) {
            setError('Todos los campos son obligatorios.');
            return;
        }

        // Validar formato de email
        if (!validateEmail(email)) {
            setError('El formato del email es inválido.');
            return;
        }

        // Validar contraseña
        if (!validatePassword(password)) {
            setError('La contraseña debe tener al menos 8 caracteres, al menos una mayúscula, un número y un carácter especial.');
            return;
        }

        try {
            const response = await fetch(`${process.env.BACKEND_URL}/api/signup`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ first_name, last_name, email, password }),
            });

            const data = await response.json();

            if (!response.ok) {
                switch (response.status) {
                    case 400:
                        throw new Error('Datos enviados incorrectos. Verifica la información proporcionada.');
                    case 401:
                        throw new Error('No autorizado. Verifica tus credenciales.');
                    case 409:
                        throw new Error('Este email ya está registrado. Intenta con otro.');
                    case 500:
                        throw new Error('Error del servidor. Por favor, intenta de nuevo más tarde.');
                    default:
                        throw new Error('Ha ocurrido un problema desconocido con el registro.');
                }
            }
            // Mostrar mensaje de éxito
            setSuccess('Usuario registrado correctamente.');

            // Esperar unos segundos antes de abrir el modal de login
            setTimeout(() => {
                actions.openLoginModal();
                setSuccess(''); // Limpiar el mensaje de éxito después de abrir el modal
            }, 3000); // Espera de 3 segundos

        } catch (error) {
            // Captura errores de red u otros imprevistos
            if (error.name === 'TypeError') {
                setError('Error de red. Verifica tu conexión a internet.');
            } else {
                setError(error.message);
            }
        }
    };

    return (
        <div className="container my-5">
            <div className="card shadow-sm">
                <div className="card-header">
                    <h2 className="card-title">Registro</h2>
                </div>
                <div className="card-body mb-3">
                    <form onSubmit={handleSignup}>
                        <div className="mb-3">
                            <label htmlFor="firstName" className="form-label">Nombre</label>
                            <input
                                type="text"
                                id="firstName"
                                className="form-control"
                                placeholder="Nombre"
                                onChange={(e) => setFirstName(e.target.value)}
                                required
                                autoComplete="off"
                            />
                        </div>
                        <div className="mb-3">
                            <label htmlFor="lastName" className="form-label">Apellidos</label>
                            <input
                                type="text"
                                id="lastName"
                                className="form-control"
                                placeholder="Apellidos"
                                onChange={(e) => setLastName(e.target.value)}
                                required
                                autoComplete="off"
                            />
                        </div>
                        <div className="mb-3">
                            <label htmlFor="email" className="form-label">Correo electrónico</label>
                            <input
                                type="email"
                                id="email"
                                className="form-control"
                                placeholder="Correo electrónico"
                                onChange={(e) => setEmail(e.target.value)}
                                required
                                autoComplete="email"
                            />
                        </div>
                        <div className="mb-3">
                            <label htmlFor="password" className="form-label">Contraseña</label>
                            <div className="position-relative">
                                <input
                                    type={showPassword ? "text" : "password"}
                                    id="password"
                                    className="form-control"
                                    placeholder="Contraseña"
                                    onChange={(e) => setPassword(e.target.value)}
                                    required
                                    autoComplete="new-password"
                                />
                                <span
                                    className="password-toggle-icon"
                                    onClick={() => setShowPassword(prev => !prev)}
                                >
                                    <i className={`fas ${showPassword ? "fa-eye" : "fa-eye-slash"}`}></i>
                                </span>
                            </div>
                        </div>
                        {success && <div className="text-center success-message">{success}</div>}
                        {error && <div className="text-center alert alert-danger">{error}</div>}
                        <button type="submit" className="btn btn-success mb-4">Registrarse</button>
                    </form>
                </div>
            </div>

            {/* Modal de Login */}
            {store.isLoginModalOpen && (
                <div className="modal fade show" style={{ display: "block" }} tabIndex="-1" role="dialog" aria-hidden="true">
                    <div className="modal-dialog" role="document">
                        <div className="modal-content">
                            <div className="modal-header">
                                <h5 className="modal-title">Iniciar Sesión</h5>
                                <button type="button" className="btn-close" onClick={actions.openLoginModal} aria-label="Cerrar" />
                            </div>
                            <div className="modal-body">
                                <Login onClose={actions.closeLoginModal} />
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};