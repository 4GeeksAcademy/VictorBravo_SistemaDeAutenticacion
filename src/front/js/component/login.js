import React, { useContext, useState, useEffect, useRef } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Context } from '../store/appContext';

const Login = ({ onClose }) => {    // Recibe la función para cerrar el modal
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [remember, setRemember] = useState(false);
    const { actions } = useContext(Context);
    const [showPassword, setShowPassword] = useState(false);
    const [loading, setLoading] = useState(false);
    const isMounted = useRef(true);
    const navigate = useNavigate();

    useEffect(() => {
        // Establecer isMounted como true cuando el componente se monta
        isMounted.current = true;

        // Limpiar la bandera cuando el componente se desmonta
        return () => {
            isMounted.current = false;
        };
    }, []);

    const handleLogin = async (e) => {
        e.preventDefault();
        setError(''); // Reset error
        setLoading(true); // Mostrar el mensaje de "Iniciando sesión"

        try {
            const resp = await fetch(`${process.env.BACKEND_URL}/api/token`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                credentials: 'include', // Envío de cookies
                body: JSON.stringify({ email, password, remember }),
            });

            const data = await resp.json();

            if (!resp.ok) {
                if (resp.status === 401) {
                    throw new Error("Las credenciales son incorrectas.");
                } else if (resp.status === 404) {
                    throw new Error("Este email no está registrado.")
                } else if (resp.status === 400) {
                    throw new Error("Formato de email o contraseña incorrectos.");
                } else {
                    throw new Error("Ha ocurrido un problema con el inicio de sesión.");
                }
            }

            // Verificar si el componente sigue montado antes de actualizar el estado o navegar
            if (isMounted.current) {
                actions.login(data); // Cambia el estado isLogged a true y guarda el nombre de usuario
                console.log('Usuario logueado:', true); // Imprime en la consola el estado de isLogged

                setTimeout(() => {
                    setLoading(false); // Ocultar el mensaje de "Iniciando sesión"
                    onClose(); // Cerrar el modal
                    navigate('/dashboard'); // Redirigir a la página de dashboard
                }, 2000); // Esperar 2 segundos antes de redirigir
            }

        } catch (error) {
            if (isMounted.current) {
                setLoading(false); // Ocultar el mensaje de "Iniciando sesión" si hay error
                setError(error.message);
            }
        }
    };

    const handleRegisterRedirect = () => {
        onClose(); // Cerrar el modal
        navigate('/signup'); // Redirigir a la página de registro
    };

    return (
        <form onSubmit={handleLogin}>
            <div className="mb-3">
                <input
                    type="email"
                    className="form-control"
                    placeholder="Correo"
                    onChange={(e) => setEmail(e.target.value)}
                    required
                />
            </div>
            <div className="mb-3 position-relative">
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
            <div className="form-check mb-3">
                <input
                    type="checkbox"
                    className="form-check-input"
                    id="remember"
                    checked={remember}
                    onChange={(e) => setRemember(e.target.checked)}
                />
                <label className="form-check-label" htmlFor="remember">Recuérdame</label>
            </div>
            <div className="d-flex flex-column justify-content-center">
                {loading && <div className="text-center alert alert-info">Iniciando sesión...</div>}
                {error && <div className="text-center alert alert-danger">{error}</div>}
                <button type="submit" className="btn btn-primary">Iniciar Sesión</button>
            </div>
            <div className="d-flex justify-content-center align-items-center mt-3">
                <span>¿No tienes una cuenta? </span>
                <button className="btn btn-link" onClick={handleRegisterRedirect}>Regístrate</button>
            </div>
        </form>
    );
};

export default Login;